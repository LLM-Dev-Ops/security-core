import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const [baseline, candidate, runtime, output] = process.argv.slice(2).map(value => resolve(value));
assert.ok(
  baseline && candidate && runtime && output,
  'usage: node evaluate-http-boundary.mjs BASELINE CANDIDATE PINNED_TOOLS OUTPUT'
);

const packageVersion = name =>
  JSON.parse(readFileSync(join(runtime, 'node_modules', name, 'package.json'), 'utf8')).version;
assert.equal(packageVersion('@metaharness/flywheel'), '0.1.12');

const {
  makeSigner,
  meetsPromotionRule,
  runFlywheelGenerations,
  verifyReplayBundle,
} = await import(pathToFileURL(join(
  runtime,
  'node_modules/@metaharness/flywheel/dist/index.js'
)));

const holdoutSource = String.raw`
const http = require('node:http');
const { createSecurityServer } = require('./dist/server.js');
const orchestrator = {
  process: async request => ({ requestId: request && request.id || 'x', allowed: true }),
  executeGate: async request => ({
    requestId: request.id,
    gate: { decision: 'allow' },
  }),
};
const server = createSecurityServer(orchestrator);
server.listen(0, '127.0.0.1', async () => {
  const port = server.address().port;
  const post = (body, headers = {}) => new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1',
      port,
      path: '/check',
      method: 'POST',
      headers: { 'Content-Length': Buffer.byteLength(body), ...headers },
    }, response => {
      let responseBody = '';
      response.on('data', chunk => { responseBody += chunk; });
      response.on('end', () => resolve({
        status: response.statusCode,
        body: responseBody,
      }));
    });
    request.on('error', reject);
    request.end(body);
  });

  const valid = JSON.stringify({ id: 'request-1', type: 'prompt', content: 'safe' });
  const cases = [
    [await post(valid), result => result.status === 415],
    [await post(JSON.stringify({
      id: 'request-2',
      type: 'prompt',
      content: 'x'.repeat(70_000),
    }), { 'Content-Type': 'application/json' }), result => result.status === 413],
    [await post(JSON.stringify({
      id: '',
      type: 'invalid',
      content: 7,
    }), { 'Content-Type': 'application/json' }), result => result.status === 422],
    [await post(JSON.stringify({
      id: 'request' + String.fromCharCode(10) + 'smuggling',
      type: 'prompt',
      content: 'safe',
    }), { 'Content-Type': 'application/json' }), result => result.status === 422],
    [await post('{bad', { 'Content-Type': 'application/json' }), result =>
      result.status === 400 && result.body === JSON.stringify({ error: 'invalid_json' })],
  ];
  process.stdout.write(JSON.stringify({ itemWins: cases.map(([value, check]) => check(value)) }));
  server.close();
});
`;

const measurements = [];
const run = (dir, argv) => {
  const child = spawnSync(argv[0], argv.slice(1), {
    cwd: dir,
    encoding: 'utf8',
    timeout: 180000,
    maxBuffer: 12 * 1024 * 1024,
  });
  assert.equal(child.signal, null, `${argv.join(' ')} timed out`);
  return {
    ok: child.status === 0,
    exit: child.status,
    stdout: child.stdout,
    stderr: child.stderr.slice(-4000),
    argv,
  };
};

const evaluateHoldout = dir => {
  const build = run(dir, ['npm', 'run', 'build']);
  assert.equal(build.exit, 0, build.stderr || build.stdout);
  const command = run(dir, [process.execPath, '-e', holdoutSource]);
  assert.equal(command.exit, 0, command.stderr || command.stdout);
  return { itemWins: JSON.parse(command.stdout).itemWins, command, commands: [build, command] };
};

const auditWithinBaseline = command => {
  try {
    const report = JSON.parse(command.stdout);
    const actual = report.metadata.vulnerabilities;
    const maximum = { info: 0, low: 0, moderate: 8, high: 26, critical: 2, total: 36 };
    return Object.entries(maximum).every(([severity, count]) => actual[severity] <= count);
  } catch {
    return false;
  }
};

const evaluateAnchors = dir => {
  const commands = [
    run(dir, ['npm', 'run', 'build']),
    run(dir, ['npm', 'test']),
    run(dir, ['npm', 'run', 'lint']),
    run(dir, ['npm', 'audit', '--omit=dev', '--json']),
  ];
  return {
    itemWins: [commands[0].ok, commands[1].ok, commands[2].ok, auditWithinBaseline(commands[3])],
    commands,
  };
};

const evaluatorFn = async (policy, suite) => {
  const dir = policy.implementation === 'candidate' ? candidate : baseline;
  const measurement = suite.id === 'http-boundary-holdout'
    ? evaluateHoldout(dir)
    : evaluateAnchors(dir);
  const wins = measurement.itemWins;
  const count = wins.filter(Boolean).length;
  measurements.push({
    implementation: policy.implementation,
    suite: suite.id,
    itemWins: wins,
    command: measurement.command,
    commands: measurement.commands,
  });
  return {
    primary: count / wins.length,
    noopRate: (wins.length - count) / wins.length,
    costPerWin: count === 0 ? 1 : 1 / count,
    regressed: suite.id === 'behavior-anchor' && count !== wins.length,
    itemWins: wins,
  };
};

const parentPath = join(baseline, 'src/server.ts');
const parentBytes = readFileSync(parentPath, 'utf8');
const result = await runFlywheelGenerations({
  rootPolicy: { implementation: 'baseline' },
  mutationTargets: ['implementation'],
  proposer: async () => ({
    value: 'candidate',
    summary: 'Bound JSON request bodies, validate security request envelopes, and replace parser or internal disclosures with stable error codes.',
    inverse: {
      path: 'src/server.ts',
      parentBytes,
      hash: createHash('sha256').update(parentBytes).digest('hex'),
    },
  }),
  evaluator: evaluatorFn,
  promotionRule: meetsPromotionRule,
  holdout: { id: 'http-boundary-holdout', items: [
    'media type',
    'body limit',
    'request shape',
    'identifier controls',
    'parser disclosure',
  ] },
  anchor: { id: 'behavior-anchor', items: [
    'TypeScript build',
    'repository tests',
    'typecheck',
    'production audit non-regression',
  ] },
  maxGenerations: 1,
  signer: makeSigner(),
  now: generation => `2026-10-24T12:15:0${generation}Z`,
  cacheEvaluations: true,
  dataSource: 'LIVE',
});

const replay = verifyReplayBundle(result.replayBundle);
assert.equal(replay.pass, true, JSON.stringify(replay));
assert.equal(result.promotions.length, 1, 'candidate must pass the frozen promotion gate');

const report = {
  schema: 1,
  versions: {
    flywheel: packageVersion('@metaharness/flywheel'),
    darwin: packageVersion('@metaharness/darwin'),
    metaharness: packageVersion('metaharness'),
  },
  suites: {
    holdout: [
      'requires application/json',
      '64 KiB JSON body limit',
      'security request shape validation',
      'control-character identifier rejection',
      'generic malformed JSON response',
    ],
    anchors: [
      'TypeScript build',
      'complete repository test suite',
      'typecheck',
      'production audit non-regression',
    ],
  },
  measurements,
  liftCurve: result.liftCurve,
  promotions: result.promotions,
  replay,
  replayBundle: result.replayBundle,
  rollback: {
    strategy: 'Revert the PR or restore the signed inverse for src/server.ts.',
    parentSha: process.env.BASELINE_SHA || null,
    inverseSha256: createHash('sha256').update(parentBytes).digest('hex'),
  },
};
writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({
  promoted: result.promotions.length,
  replayPass: replay.pass,
  liftCurve: result.liftCurve,
  gateFingerprint: result.replayBundle.gateFingerprint,
  output,
}));

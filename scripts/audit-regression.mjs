import { spawnSync } from 'node:child_process';

const baseline = Object.freeze({
  info: 0,
  low: 0,
  moderate: 8,
  high: 26,
  critical: 2,
  total: 36
});

const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const result = spawnSync(npm, ['audit', '--omit=dev', '--json'], {
  cwd: process.cwd(),
  encoding: 'utf8',
  shell: false
});

if (result.error) {
  throw result.error;
}

let report;
try {
  report = JSON.parse(result.stdout);
} catch {
  console.error(result.stderr || result.stdout);
  throw new Error('npm audit did not return valid JSON');
}

const actual = report?.metadata?.vulnerabilities;
if (!actual) {
  throw new Error('npm audit report omitted vulnerability metadata');
}

const regressions = Object.entries(baseline)
  .filter(([severity, maximum]) => Number(actual[severity] ?? 0) > maximum)
  .map(([severity, maximum]) => `${severity}: ${actual[severity]} > ${maximum}`);

console.log(JSON.stringify({ baseline, actual }, null, 2));
if (regressions.length > 0) {
  console.error(`Production audit regression: ${regressions.join(', ')}`);
  process.exit(1);
}

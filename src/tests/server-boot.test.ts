// ADR-0002: the process refuses to start when it cannot reach its upstreams.
//
// ADR-0001 made an unconfigured adapter an error rather than a permissive mode.
// These tests assert the same rule one layer up: a security-core that cannot be
// configured must fail to start, not start in a state where it cannot evaluate.
import { describe, it } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import type { AddressInfo } from 'node:net';
import type http from 'node:http';
import { startServer } from '../server.js';
import { UpstreamConfigurationError } from '../adapters/factory.js';

const REPO_ROOT = path.resolve(__dirname, '..', '..');

const ALL_URLS: Record<string, string> = {
  POLICY_ENGINE_URL: 'http://127.0.0.1:1',
  SHIELD_URL: 'http://127.0.0.1:1',
  EDGE_AGENT_URL: 'http://127.0.0.1:1',
  INCIDENT_MANAGER_URL: 'http://127.0.0.1:1',
  CONFIG_MANAGER_URL: 'http://127.0.0.1:1'
};

/** Boots dist/server.js as a real child process, as Cloud Run would. */
function bootServerProcess(env: Record<string, string>) {
  return spawnSync(process.execPath, ['dist/server.js'], {
    cwd: REPO_ROOT,
    env: { PATH: process.env.PATH ?? '', ...env },
    encoding: 'utf8',
    timeout: 20_000
  });
}

async function listening(env: Record<string, string>): Promise<{ url: string; close(): Promise<void> }> {
  const server = startServer({ ...env, PORT: '0' } as NodeJS.ProcessEnv);
  await new Promise<void>(resolve => server.once('listening', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>(resolve => { (server as http.Server).close(() => resolve()); })
  };
}

describe('startServer refuses to boot without upstream configuration', () => {
  it('throws UpstreamConfigurationError instead of listening', () => {
    assert.throws(
      () => startServer({ PORT: '0' } as NodeJS.ProcessEnv),
      (err: unknown) => err instanceof UpstreamConfigurationError
    );
  });

  it('names every missing variable before any socket is opened', () => {
    let message = '';
    try {
      startServer({ PORT: '0' } as NodeJS.ProcessEnv);
    } catch (err) {
      message = (err as Error).message;
    }
    for (const name of Object.keys(ALL_URLS)) {
      assert.ok(message.includes(name), `startup error must name ${name}`);
    }
  });

  it('refuses when only some URLs are set', () => {
    assert.throws(
      () => startServer({ PORT: '0', POLICY_ENGINE_URL: 'https://policy.example' } as NodeJS.ProcessEnv),
      (err: unknown) => err instanceof UpstreamConfigurationError
        && (err as Error).message.includes('SHIELD_URL')
    );
  });
});

describe('dist/server.js exits non-zero on misconfiguration', () => {
  it('exits non-zero and never listens with an empty environment', () => {
    const child = bootServerProcess({});
    assert.notStrictEqual(child.status, 0, `expected non-zero exit, got ${child.status}`);
    assert.match(child.stderr ?? '', /Refusing to start/);
    assert.ok(
      !(child.stdout ?? '').includes('Server listening'),
      'the process must not report listening when it is misconfigured'
    );
  });

  it('names all five missing variables on stderr', () => {
    const stderr = bootServerProcess({}).stderr ?? '';
    for (const name of Object.keys(ALL_URLS)) {
      assert.ok(stderr.includes(name), `stderr must name ${name}`);
    }
  });

  it('names the remaining four when only POLICY_ENGINE_URL is set', () => {
    const stderr = bootServerProcess({ POLICY_ENGINE_URL: ALL_URLS.POLICY_ENGINE_URL }).stderr ?? '';
    assert.ok(!stderr.includes('POLICY_ENGINE_URL'), 'the configured variable must not be reported missing');
    assert.ok(stderr.includes('SHIELD_URL'));
    assert.ok(stderr.includes('EDGE_AGENT_URL'));
    assert.ok(stderr.includes('INCIDENT_MANAGER_URL'));
    assert.ok(stderr.includes('CONFIG_MANAGER_URL'));
  });

  it('exits non-zero on a malformed URL', () => {
    const child = bootServerProcess({ ...ALL_URLS, SHIELD_URL: 'notaurl' });
    assert.notStrictEqual(child.status, 0);
    assert.match(child.stderr ?? '', /SHIELD_URL is not a valid http\(s\) URL: "notaurl"/);
  });

  // The failure mode ADR-0002 exists to remove: a misconfigured production
  // process must not quietly become a pass-through simulator.
  it('does not fall back to the simulator under NODE_ENV=production', () => {
    const child = bootServerProcess({ NODE_ENV: 'production' });
    assert.notStrictEqual(child.status, 0);
    assert.ok(!(child.stdout ?? '').includes('Server listening'));
    assert.ok(!(child.stdout ?? '').includes('SIMULATOR'));
  });

  it('still refuses an explicit simulator opt-in under NODE_ENV=production', () => {
    const child = bootServerProcess({ NODE_ENV: 'production', SECURITY_CORE_SIMULATOR: '1' });
    assert.notStrictEqual(child.status, 0);
    assert.ok(!(child.stdout ?? '').includes('Server listening'));
  });
});

describe('startServer boots when all five URLs are configured', () => {
  it('listens and serves /health', async () => {
    const server = await listening(ALL_URLS);
    try {
      const res = await fetch(`${server.url}/health`);
      assert.strictEqual(res.status, 200);
      const body = await res.json() as { status: string; service: string };
      assert.strictEqual(body.status, 'healthy');
      assert.strictEqual(body.service, 'security-core');
    } finally {
      await server.close();
    }
  });

  // ADR-0001's property, asserted end-to-end through the HTTP layer for the
  // first time: an unreachable policy engine denies, it does not permit.
  it('denies at the gate when the policy engine is unreachable', async () => {
    const server = await listening({ ...ALL_URLS, SECURITY_UPSTREAM_TIMEOUT_MS: '1000' });
    try {
      const res = await fetch(`${server.url}/gate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          request: { id: 'boot-1', type: 'prompt', content: 'hello' }
        })
      });

      assert.strictEqual(res.status, 403, 'an unavailable policy engine must not produce a 200');
      const body = await res.json() as { gate: { decision: string; violations?: Array<{ policy: string }> } };
      assert.strictEqual(body.gate.decision, 'deny');
      assert.strictEqual(body.gate.violations?.[0].policy, 'policy-engine-unavailable');
    } finally {
      await server.close();
    }
  });
});

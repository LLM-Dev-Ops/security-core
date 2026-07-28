// ADR-0002: environment-to-client resolution.
//
// The factory is the only place a URL enters the process. It has no defaults
// and no simulator fallback, so these tests are the unit-level statement of the
// fail-closed-startup rule. Every case injects an `env` object rather than
// mutating process.env.
import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  resolveUpstreamConfig,
  createClientCollection,
  UpstreamConfigurationError
} from '../adapters/factory.js';
import { DEFAULT_UPSTREAM_TIMEOUT_MS } from '../adapters/http/client.js';

const ALL_URLS = {
  POLICY_ENGINE_URL: 'https://policy-engine.example',
  SHIELD_URL: 'https://shield.example',
  EDGE_AGENT_URL: 'https://edge-agent.example',
  INCIDENT_MANAGER_URL: 'https://incident-manager.example',
  CONFIG_MANAGER_URL: 'https://config-manager.example'
} as NodeJS.ProcessEnv;

const REQUIRED = [
  'POLICY_ENGINE_URL',
  'SHIELD_URL',
  'EDGE_AGENT_URL',
  'INCIDENT_MANAGER_URL',
  'CONFIG_MANAGER_URL'
];

function withoutVar(name: string): NodeJS.ProcessEnv {
  const env = { ...ALL_URLS };
  delete env[name];
  return env;
}

describe('resolveUpstreamConfig — all present', () => {
  it('resolves every URL', () => {
    const config = resolveUpstreamConfig(ALL_URLS);
    assert.strictEqual(config.policyEngineUrl, 'https://policy-engine.example');
    assert.strictEqual(config.shieldUrl, 'https://shield.example');
    assert.strictEqual(config.edgeAgentUrl, 'https://edge-agent.example');
    assert.strictEqual(config.incidentManagerUrl, 'https://incident-manager.example');
    assert.strictEqual(config.configManagerUrl, 'https://config-manager.example');
  });

  it('defaults the upstream timeout', () => {
    assert.strictEqual(resolveUpstreamConfig(ALL_URLS).timeoutMs, DEFAULT_UPSTREAM_TIMEOUT_MS);
  });

  it('honours SECURITY_UPSTREAM_TIMEOUT_MS', () => {
    const config = resolveUpstreamConfig({ ...ALL_URLS, SECURITY_UPSTREAM_TIMEOUT_MS: '1500' });
    assert.strictEqual(config.timeoutMs, 1500);
  });

  it('rejects a non-positive timeout rather than silently defaulting', () => {
    assert.throws(
      () => resolveUpstreamConfig({ ...ALL_URLS, SECURITY_UPSTREAM_TIMEOUT_MS: '0' }),
      (err: unknown) => err instanceof UpstreamConfigurationError
        && /SECURITY_UPSTREAM_TIMEOUT_MS/.test((err as Error).message)
    );
  });

  it('accepts plain http for local upstreams', () => {
    const config = resolveUpstreamConfig({ ...ALL_URLS, SHIELD_URL: 'http://127.0.0.1:8081' });
    assert.strictEqual(config.shieldUrl, 'http://127.0.0.1:8081');
  });

  it('leaves request paths unset so each client uses its own default', () => {
    const { paths } = resolveUpstreamConfig(ALL_URLS);
    assert.strictEqual(paths.policyEvaluate, undefined);
    assert.strictEqual(paths.shieldFilter, undefined);
    assert.strictEqual(paths.configManager.get, undefined);
  });

  it('carries path overrides through', () => {
    const { paths } = resolveUpstreamConfig({
      ...ALL_URLS,
      POLICY_EVALUATE_PATH: '/v2/evaluate',
      CONFIG_GET_PATH: '/v2/config'
    });
    assert.strictEqual(paths.policyEvaluate, '/v2/evaluate');
    assert.strictEqual(paths.configManager.get, '/v2/config');
  });
});

describe('resolveUpstreamConfig — missing variables', () => {
  it('refuses an empty environment and names all five', () => {
    let message = '';
    assert.throws(
      () => resolveUpstreamConfig({} as NodeJS.ProcessEnv),
      (err: unknown) => {
        assert.ok(err instanceof UpstreamConfigurationError);
        message = (err as Error).message;
        return true;
      }
    );
    for (const name of REQUIRED) {
      assert.ok(message.includes(name), `error must name ${name}`);
    }
    assert.match(message, /Refusing to start/);
  });

  it('names every missing variable, not just the first', () => {
    let message = '';
    try {
      resolveUpstreamConfig({ POLICY_ENGINE_URL: 'https://policy-engine.example' } as NodeJS.ProcessEnv);
    } catch (err) {
      message = (err as Error).message;
    }
    assert.ok(!message.includes('POLICY_ENGINE_URL'), 'the configured variable must not be reported missing');
    for (const name of REQUIRED.slice(1)) {
      assert.ok(message.includes(name), `error must name ${name}`);
    }
  });

  // Each variable is individually mandatory: none of the five has a default.
  for (const name of REQUIRED) {
    it(`refuses to resolve when ${name} is absent`, () => {
      assert.throws(
        () => resolveUpstreamConfig(withoutVar(name)),
        (err: unknown) => err instanceof UpstreamConfigurationError
          && (err as Error).message.includes(name)
      );
    });
  }

  it('treats a whitespace-only value as absent', () => {
    assert.throws(
      () => resolveUpstreamConfig({ ...ALL_URLS, SHIELD_URL: '   ' }),
      (err: unknown) => (err as Error).message.includes('SHIELD_URL')
    );
  });

  it('never falls back to a simulator or an allow', () => {
    let message = '';
    try {
      resolveUpstreamConfig({} as NodeJS.ProcessEnv);
    } catch (err) {
      message = (err as Error).message;
    }
    assert.match(message, /will not fall back to a simulator or an allow/);
  });
});

describe('resolveUpstreamConfig — malformed values', () => {
  it('rejects a value that is not a URL', () => {
    assert.throws(
      () => resolveUpstreamConfig({ ...ALL_URLS, SHIELD_URL: 'notaurl' }),
      (err: unknown) => err instanceof UpstreamConfigurationError
        && (err as Error).message === 'SHIELD_URL is not a valid http(s) URL: "notaurl"'
    );
  });

  it('rejects a non-http(s) protocol', () => {
    assert.throws(
      () => resolveUpstreamConfig({ ...ALL_URLS, POLICY_ENGINE_URL: 'ftp://policy.example' }),
      (err: unknown) => err instanceof UpstreamConfigurationError
        && (err as Error).message.includes('POLICY_ENGINE_URL')
    );
  });

  it('rejects a bare host with no scheme', () => {
    assert.throws(
      () => resolveUpstreamConfig({ ...ALL_URLS, EDGE_AGENT_URL: 'edge-agent.example' }),
      (err: unknown) => err instanceof UpstreamConfigurationError
    );
  });

  it('reports a malformed URL rather than reporting it missing', () => {
    let message = '';
    try {
      resolveUpstreamConfig({ ...ALL_URLS, CONFIG_MANAGER_URL: 'nope' });
    } catch (err) {
      message = (err as Error).message;
    }
    assert.match(message, /is not a valid http\(s\) URL/);
    assert.ok(!message.includes('Refusing to start'));
  });
});

describe('createClientCollection', () => {
  it('builds all five clients when the environment is complete', () => {
    const clients = createClientCollection(ALL_URLS);
    assert.strictEqual(typeof clients.policyEngine.evaluate, 'function');
    assert.strictEqual(typeof clients.shield.filter, 'function');
    assert.strictEqual(typeof clients.edgeAgent.enforce, 'function');
    assert.strictEqual(typeof clients.incidentManager.emit, 'function');
    assert.strictEqual(typeof clients.configManager.get, 'function');
    assert.strictEqual(typeof clients.configManager.getSecret, 'function');
  });

  it('propagates the configuration error when a URL is missing', () => {
    assert.throws(
      () => createClientCollection(withoutVar('INCIDENT_MANAGER_URL')),
      (err: unknown) => err instanceof UpstreamConfigurationError
        && (err as Error).message.includes('INCIDENT_MANAGER_URL')
    );
  });
});

// Tests for non-blocking router (POST /v1/scan, POST /v1/audit/record)
import { describe, it } from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { routeScan, routeAuditRecord, type RouterUpstreams } from '../services/router.js';

interface Stub {
  upstreams: RouterUpstreams;
  received: string[];
  /** Resolves once `count` requests have landed, or after a 5s deadline. */
  settle(count: number): Promise<void>;
  close(): Promise<void>;
}

/**
 * A local stub stands in for every upstream, so the router's fire-and-forget
 * dispatch can be observed without contacting a deployed service. Each test
 * gets its own so late-arriving dispatches cannot leak across tests.
 */
async function stubUpstreams(): Promise<Stub> {
  const received: string[] = [];
  const server = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      received.push(req.url ?? '');
      res.writeHead(202, { 'Content-Type': 'application/json' });
      res.end('{}');
    });
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  const url = `http://127.0.0.1:${port}`;

  return {
    upstreams: {
      shieldUrl: url,
      edgeAgentUrl: url,
      incidentManagerUrl: url,
      policyEngineUrl: url
    },
    received,
    async settle(count) {
      const deadline = Date.now() + 5000;
      while (received.length < count && Date.now() < deadline) {
        await new Promise(resolve => setTimeout(resolve, 10));
      }
    },
    close: () => new Promise<void>(resolve => { server.close(() => resolve()); })
  };
}

// Deliberately unroutable: the routing decision is returned synchronously and
// does not depend on any dispatch succeeding.
const unreachable: RouterUpstreams = {
  shieldUrl: 'http://127.0.0.1:1',
  edgeAgentUrl: 'http://127.0.0.1:1',
  incidentManagerUrl: 'http://127.0.0.1:1',
  policyEngineUrl: 'http://127.0.0.1:1'
};

describe('routeScan', () => {
  it('returns accepted with routed_to containing shield and edge-agent', () => {
    const result = routeScan({
      artifacts: ['file.py'],
      source: 'ci-pipeline',
      execution_id: 'exec-001'
    }, unreachable);
    assert.strictEqual(result.accepted, true);
    assert.deepStrictEqual(result.routed_to, ['llm-shield', 'llm-edge-agent']);
  });

  it('handles empty payload', () => {
    const result = routeScan({}, unreachable);
    assert.strictEqual(result.accepted, true);
    assert.strictEqual(result.routed_to.length, 2);
  });
});

describe('routeAuditRecord', () => {
  it('returns accepted with routed_to containing incident-manager and policy-engine', () => {
    const result = routeAuditRecord({
      event: 'policy_violation',
      severity: 'high',
      userId: 'user-42'
    }, unreachable);
    assert.strictEqual(result.accepted, true);
    assert.deepStrictEqual(result.routed_to, ['llm-incident-manager', 'llm-policy-engine']);
  });

  it('handles payload without event field', () => {
    const result = routeAuditRecord({ detail: 'something' }, unreachable);
    assert.strictEqual(result.accepted, true);
    assert.strictEqual(result.routed_to.length, 2);
  });
});

// ADR-0002: router.ts previously defaulted to the `llm-shield-dev` deployment
// whenever LLM_SHIELD_URL was unset, so a production process could silently fan
// out to a development service. Every URL must now come from the caller.
describe('router dispatches only to the upstreams it was given', () => {
  it('sends scan traffic to the supplied shield and edge-agent URLs', async () => {
    const stub = await stubUpstreams();
    try {
      routeScan({ artifacts: ['a.py'] }, stub.upstreams);
      await stub.settle(2);
      assert.deepStrictEqual(
        stub.received.slice().sort(),
        ['/agents/tool-invocation/execute', '/api/v1/scan']
      );
    } finally {
      await stub.close();
    }
  });

  it('sends audit traffic to the supplied incident-manager and policy-engine URLs', async () => {
    const stub = await stubUpstreams();
    try {
      routeAuditRecord({ event: 'policy_violation' }, stub.upstreams);
      await stub.settle(2);
      assert.deepStrictEqual(
        stub.received.slice().sort(),
        ['/api/evaluate', '/api/v1/events']
      );
    } finally {
      await stub.close();
    }
  });
});

// Tests for SecurityOrchestrator
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { SecurityOrchestrator } from '../services/orchestrator.js';
import { createShieldAdapter } from '../adapters/shield.js';
import { createEdgeAgentAdapter } from '../adapters/edge-agent.js';
import { createIncidentAdapter } from '../adapters/incident.js';
import { createPolicyAdapter } from '../adapters/policy.js';
import { createConfigAdapter } from '../adapters/config.js';
import type { SecurityRequest } from '../lib.js';

function createTestOrchestrator(overrides: Partial<Parameters<typeof SecurityOrchestrator['prototype']['process']>[0]> = {}) {
  return new SecurityOrchestrator({
    shield: createShieldAdapter(),
    edgeAgent: createEdgeAgentAdapter(),
    incident: createIncidentAdapter(),
    policy: createPolicyAdapter(),
    config: createConfigAdapter()
  });
}

describe('SecurityOrchestrator', () => {
  it('should allow valid requests in simulator mode', async () => {
    const orchestrator = createTestOrchestrator();
    const request: SecurityRequest = { id: 'test-1', type: 'prompt', content: 'Hello world' };
    const result = await orchestrator.process(request);
    assert.strictEqual(result.allowed, true);
    assert.strictEqual(result.requestId, 'test-1');
  });

  it('should process output type requests', async () => {
    const orchestrator = createTestOrchestrator();
    const request: SecurityRequest = { id: 'test-2', type: 'output', content: 'Response text' };
    const result = await orchestrator.process(request);
    assert.strictEqual(result.allowed, true);
    assert.strictEqual(result.filtered, 'Response text');
  });

  it('should handle runtime type requests', async () => {
    const orchestrator = createTestOrchestrator();
    const request: SecurityRequest = { id: 'test-3', type: 'runtime', content: 'Runtime check' };
    const result = await orchestrator.process(request);
    assert.strictEqual(result.allowed, true);
  });

  it('should include request metadata', async () => {
    const orchestrator = createTestOrchestrator();
    const request: SecurityRequest = {
      id: 'test-4',
      type: 'prompt',
      content: 'Test',
      metadata: { userId: 'user-123', sessionId: 'sess-456' }
    };
    const result = await orchestrator.process(request);
    assert.strictEqual(result.requestId, 'test-4');
  });
});

describe('Adapters', () => {
  it('shield adapter should pass through in simulator mode', async () => {
    const adapter = createShieldAdapter();
    const result = await adapter.filter('test content', 'prompt');
    assert.strictEqual(result.filtered, 'test content');
    assert.deepStrictEqual(result.redactions, []);
  });

  it('edge agent adapter should enforce in simulator mode', async () => {
    const adapter = createEdgeAgentAdapter();
    const request: SecurityRequest = { id: 'test', type: 'prompt', content: 'test' };
    const result = await adapter.enforce(request, { policyId: 'test', action: 'allow' });
    assert.strictEqual(result.enforced, true);
  });

  it('incident adapter should generate IDs in simulator mode', async () => {
    const adapter = createIncidentAdapter();
    const result = await adapter.emit({ type: 'violation', severity: 'low', source: 'test', details: {} });
    assert.ok(result.incidentId.startsWith('sim-incident-'));
  });

  it('policy adapter should return default allow in simulator mode', async () => {
    const adapter = createPolicyAdapter();
    const request: SecurityRequest = { id: 'test', type: 'prompt', content: 'test' };
    const result = await adapter.evaluate(request);
    assert.strictEqual(result[0].action, 'allow');
  });

  it('config adapter should return undefined in simulator mode', async () => {
    const adapter = createConfigAdapter();
    const result = await adapter.get('any.key');
    assert.strictEqual(result, undefined);
  });
});

// Tests for SecurityOrchestrator
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createShieldAdapter } from '../adapters/shield.js';
import { createEdgeAgentAdapter } from '../adapters/edge-agent.js';
import { createIncidentAdapter } from '../adapters/incident.js';
import { createPolicyAdapter } from '../adapters/policy.js';
import { createConfigAdapter } from '../adapters/config.js';
import { AdapterNotConfiguredError, UpstreamResponseError } from '../adapters/types.js';
import {
  createTestOrchestrator,
  allowPolicyEngine,
  passThroughShield,
  enforcingEdgeAgent,
  recordingIncidentManager,
  emptyConfigManager
} from './doubles.js';
import type { SecurityRequest } from '../lib.js';

describe('SecurityOrchestrator', () => {
  it('should allow valid requests with a configured policy engine', async () => {
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

  it('process() should not allow when the policy engine is unavailable', async () => {
    const orchestrator = createTestOrchestrator({
      policy: { async evaluate(): Promise<never> { throw new Error('policy down'); } }
    });
    const request: SecurityRequest = { id: 'test-5', type: 'prompt', content: 'Test' };
    const result = await orchestrator.process(request);

    assert.strictEqual(result.allowed, false);
    assert.strictEqual(result.violations?.[0].policy, 'policy-engine-unavailable');
    assert.strictEqual(result.violations?.[0].severity, 'critical');
  });

  it('process() should not allow when the shield is unavailable', async () => {
    const orchestrator = createTestOrchestrator({
      shield: { async filter(): Promise<never> { throw new Error('shield down'); } }
    });
    const request: SecurityRequest = { id: 'test-6', type: 'prompt', content: 'Test' };
    const result = await orchestrator.process(request);

    assert.strictEqual(result.allowed, false);
    assert.strictEqual(result.violations?.[0].policy, 'shield-unavailable');
  });
});

describe('Adapters - fail closed on missing client', () => {
  it('shield adapter should throw with no client', () => {
    assert.throws(() => createShieldAdapter(), AdapterNotConfiguredError);
  });

  it('edge agent adapter should throw with no client', () => {
    assert.throws(() => createEdgeAgentAdapter(), AdapterNotConfiguredError);
  });

  it('incident adapter should throw with no client', () => {
    assert.throws(() => createIncidentAdapter(), AdapterNotConfiguredError);
  });

  it('policy adapter should throw with no client', () => {
    assert.throws(() => createPolicyAdapter(), AdapterNotConfiguredError);
  });

  it('config adapter should throw with no client', () => {
    assert.throws(() => createConfigAdapter(), AdapterNotConfiguredError);
  });
});

describe('Adapters - delegate to configured clients', () => {
  it('shield adapter should return the upstream filter result', async () => {
    const adapter = createShieldAdapter(passThroughShield);
    const result = await adapter.filter('test content', 'prompt');
    assert.strictEqual(result.filtered, 'test content');
    assert.deepStrictEqual(result.redactions, []);
  });

  it('edge agent adapter should return the upstream enforcement result', async () => {
    const adapter = createEdgeAgentAdapter(enforcingEdgeAgent);
    const request: SecurityRequest = { id: 'test', type: 'prompt', content: 'test' };
    const result = await adapter.enforce(request, { policyId: 'test', action: 'allow' });
    assert.strictEqual(result.enforced, true);
  });

  it('incident adapter should return the upstream incident id', async () => {
    const adapter = createIncidentAdapter(recordingIncidentManager);
    const result = await adapter.emit({ type: 'violation', severity: 'low', source: 'test', details: {} });
    assert.ok(result.incidentId.startsWith('test-incident-'));
  });

  it('policy adapter should return the upstream decisions', async () => {
    const adapter = createPolicyAdapter(allowPolicyEngine);
    const request: SecurityRequest = { id: 'test', type: 'prompt', content: 'test' };
    const result = await adapter.evaluate(request);
    assert.strictEqual(result[0].action, 'allow');
  });

  it('config adapter should return undefined for unset keys', async () => {
    const adapter = createConfigAdapter(emptyConfigManager);
    assert.strictEqual(await adapter.get('any.key'), undefined);
    assert.strictEqual(await adapter.getSecret('any.secret'), undefined);
  });
});

describe('Adapters - runtime validation at the trust boundary', () => {
  it('policy adapter should reject a non-array response', async () => {
    const adapter = createPolicyAdapter({ async evaluate() { return undefined as never; } });
    await assert.rejects(
      () => adapter.evaluate({ id: 'v1', type: 'prompt', content: 'x' }),
      UpstreamResponseError
    );
  });

  it('policy adapter should reject decisions with an unknown action', async () => {
    const adapter = createPolicyAdapter({
      async evaluate() { return [{ policyId: 'p', action: 'permit' }] as never; }
    });
    await assert.rejects(
      () => adapter.evaluate({ id: 'v2', type: 'prompt', content: 'x' }),
      UpstreamResponseError
    );
  });

  it('shield adapter should reject a response without a filtered string', async () => {
    const adapter = createShieldAdapter({ async filter() { return {} as never; } });
    await assert.rejects(() => adapter.filter('x', 'prompt'), UpstreamResponseError);
  });

  it('edge agent adapter should reject a response without an enforced boolean', async () => {
    const adapter = createEdgeAgentAdapter({ async enforce() { return {} as never; } });
    await assert.rejects(
      () => adapter.enforce({ id: 'v3', type: 'prompt', content: 'x' }, { policyId: 'p', action: 'allow' }),
      UpstreamResponseError
    );
  });

  it('incident adapter should reject a response without an incident id', async () => {
    const adapter = createIncidentAdapter({ async emit() { return {} as never; } });
    await assert.rejects(
      () => adapter.emit({ type: 'violation', severity: 'low', source: 'test', details: {} }),
      UpstreamResponseError
    );
  });
});

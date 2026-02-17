// Tests for non-blocking router (POST /v1/scan, POST /v1/audit/record)
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { routeScan, routeAuditRecord } from '../services/router.js';

describe('routeScan', () => {
  it('returns accepted with routed_to containing shield and edge-agent', () => {
    const result = routeScan({
      artifacts: ['file.py'],
      source: 'ci-pipeline',
      execution_id: 'exec-001'
    });
    assert.strictEqual(result.accepted, true);
    assert.deepStrictEqual(result.routed_to, ['llm-shield', 'llm-edge-agent']);
  });

  it('handles empty payload', () => {
    const result = routeScan({});
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
    });
    assert.strictEqual(result.accepted, true);
    assert.deepStrictEqual(result.routed_to, ['llm-incident-manager', 'llm-policy-engine']);
  });

  it('handles payload without event field', () => {
    const result = routeAuditRecord({ detail: 'something' });
    assert.strictEqual(result.accepted, true);
    assert.strictEqual(result.routed_to.length, 2);
  });
});

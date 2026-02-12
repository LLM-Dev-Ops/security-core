// Tests for Security-Core gate semantics
// Security is a gate, not an observer.
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { SecurityOrchestrator } from '../services/orchestrator.js';
import { createShieldAdapter } from '../adapters/shield.js';
import { createEdgeAgentAdapter } from '../adapters/edge-agent.js';
import { createIncidentAdapter } from '../adapters/incident.js';
import { createPolicyAdapter } from '../adapters/policy.js';
import { createConfigAdapter } from '../adapters/config.js';
import type { SecurityRequest, PolicyDecision } from '../lib.js';
import type { ExecutionSpan } from '../execution/types.js';

function createTestOrchestrator(overrides?: {
  policy?: { evaluate: Function };
  shield?: { filter: Function };
}) {
  return new SecurityOrchestrator({
    shield: createShieldAdapter(overrides?.shield),
    edgeAgent: createEdgeAgentAdapter(),
    incident: createIncidentAdapter(),
    policy: createPolicyAdapter(overrides?.policy),
    config: createConfigAdapter()
  });
}

const baseRequest: SecurityRequest = { id: 'gate-1', type: 'prompt', content: 'Test content' };

// ============================================================================
// gate() - explicit decision semantics
// ============================================================================

describe('gate() - decision semantics', () => {
  it('should return explicit allow decision when all policies allow', async () => {
    const orchestrator = createTestOrchestrator();
    const result = await orchestrator.gate(baseRequest);

    assert.strictEqual(result.decision, 'allow');
    assert.strictEqual(result.requestId, 'gate-1');
    assert.strictEqual(result.policyExempt, false);
  });

  it('should return explicit deny decision when a policy denies', async () => {
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          return [{ policyId: 'block-policy', action: 'deny', reason: 'Blocked' }];
        }
      }
    });
    const result = await orchestrator.gate(baseRequest);

    assert.strictEqual(result.decision, 'deny');
    assert.ok(result.violations);
    assert.ok(result.violations.some(v => v.policy === 'block-policy'));
    assert.ok(result.incidentId);
  });

  it('should return require-approval decision when a policy requires approval', async () => {
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          return [{ policyId: 'approval-policy', action: 'require-approval', reason: 'Needs review' }];
        }
      }
    });
    const result = await orchestrator.gate(baseRequest);

    assert.strictEqual(result.decision, 'require-approval');
    assert.ok(result.violations);
    assert.ok(result.violations.some(v => v.policy === 'approval-policy'));
    assert.ok(result.incidentId);
  });

  it('should use most restrictive decision (deny > require-approval)', async () => {
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          return [
            { policyId: 'approval-policy', action: 'require-approval' },
            { policyId: 'deny-policy', action: 'deny' }
          ];
        }
      }
    });
    const result = await orchestrator.gate(baseRequest);

    assert.strictEqual(result.decision, 'deny');
  });

  it('should use most restrictive decision (require-approval > allow)', async () => {
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          return [
            { policyId: 'ok-policy', action: 'allow' },
            { policyId: 'approval-policy', action: 'require-approval' }
          ];
        }
      }
    });
    const result = await orchestrator.gate(baseRequest);

    assert.strictEqual(result.decision, 'require-approval');
  });

  it('should treat filter/redact as allow for gate decision', async () => {
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          return [{ policyId: 'filter-policy', action: 'filter' }];
        }
      }
    });
    const result = await orchestrator.gate(baseRequest);

    assert.strictEqual(result.decision, 'allow');
    assert.ok(result.violations);
    assert.strictEqual(result.violations[0].policy, 'filter-policy');
  });
});

// ============================================================================
// gate() - mandatory Shield and Policy-Engine invocation
// ============================================================================

describe('gate() - mandatory service invocation', () => {
  it('should ALWAYS call LLM-Policy-Engine', async () => {
    let policyCalled = false;
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          policyCalled = true;
          return [{ policyId: 'default', action: 'allow' }];
        }
      }
    });
    await orchestrator.gate(baseRequest);

    assert.strictEqual(policyCalled, true, 'LLM-Policy-Engine must always be invoked');
  });

  it('should ALWAYS call LLM-Shield (unconditional)', async () => {
    let shieldCalled = false;
    const orchestrator = createTestOrchestrator({
      shield: {
        async filter() {
          shieldCalled = true;
          return { filtered: 'filtered', redactions: [] };
        }
      }
    });
    await orchestrator.gate(baseRequest);

    assert.strictEqual(shieldCalled, true, 'LLM-Shield must always be invoked');
  });

  it('should call LLM-Shield even when all policies allow', async () => {
    let shieldCalled = false;
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          return [{ policyId: 'default', action: 'allow' }];
        }
      },
      shield: {
        async filter() {
          shieldCalled = true;
          return { filtered: 'filtered', redactions: [] };
        }
      }
    });
    await orchestrator.gate(baseRequest);

    assert.strictEqual(shieldCalled, true, 'LLM-Shield must be called even when all policies allow');
  });

  it('should call LLM-Shield even for runtime type requests', async () => {
    let shieldCalled = false;
    const orchestrator = createTestOrchestrator({
      shield: {
        async filter() {
          shieldCalled = true;
          return { filtered: 'filtered', redactions: [] };
        }
      }
    });
    await orchestrator.gate({ id: 'gate-rt', type: 'runtime', content: 'Runtime check' });

    assert.strictEqual(shieldCalled, true, 'LLM-Shield must be called for runtime requests');
  });

  it('should include shieldResult in gate result', async () => {
    const orchestrator = createTestOrchestrator({
      shield: {
        async filter() {
          return { filtered: 'sanitized', redactions: [{ start: 0, end: 4, reason: 'PII' }] };
        }
      }
    });
    const result = await orchestrator.gate(baseRequest);

    assert.strictEqual(result.shieldResult.filtered, 'sanitized');
    assert.ok(result.shieldResult.redactions);
    assert.strictEqual(result.shieldResult.redactions!.length, 1);
    assert.strictEqual(result.shieldResult.redactions![0].reason, 'PII');
  });

  it('should include all policy decisions in gate result', async () => {
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          return [
            { policyId: 'p1', action: 'allow' },
            { policyId: 'p2', action: 'filter' }
          ];
        }
      }
    });
    const result = await orchestrator.gate(baseRequest);

    assert.strictEqual(result.policyDecisions.length, 2);
    assert.strictEqual(result.policyDecisions[0].policyId, 'p1');
    assert.strictEqual(result.policyDecisions[1].policyId, 'p2');
  });
});

// ============================================================================
// gate() - policy exemption
// ============================================================================

describe('gate() - policy exemption', () => {
  it('should allow when policy-exempt even if policies would deny', async () => {
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          return [{ policyId: 'deny-policy', action: 'deny', reason: 'Blocked' }];
        }
      }
    });
    const result = await orchestrator.gate(baseRequest, { policyExempt: true });

    assert.strictEqual(result.decision, 'allow');
    assert.strictEqual(result.policyExempt, true);
  });

  it('should preserve audit trail when policy-exempt', async () => {
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          return [{ policyId: 'deny-policy', action: 'deny', reason: 'Blocked' }];
        }
      }
    });
    const result = await orchestrator.gate(baseRequest, { policyExempt: true });

    assert.strictEqual(result.policyDecisions[0].action, 'allow');
    assert.ok(result.policyDecisions[0].reason?.includes('policy-exempt'));
    assert.ok(result.policyDecisions[0].reason?.includes('original: deny'));
  });

  it('should still call Shield when policy-exempt', async () => {
    let shieldCalled = false;
    const orchestrator = createTestOrchestrator({
      shield: {
        async filter() {
          shieldCalled = true;
          return { filtered: 'filtered', redactions: [] };
        }
      }
    });
    await orchestrator.gate(baseRequest, { policyExempt: true });

    assert.strictEqual(shieldCalled, true);
  });

  it('should still call Policy-Engine when policy-exempt', async () => {
    let policyCalled = false;
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          policyCalled = true;
          return [{ policyId: 'default', action: 'allow' }];
        }
      }
    });
    await orchestrator.gate(baseRequest, { policyExempt: true });

    assert.strictEqual(policyCalled, true, 'Policy-Engine must be called even when exempt for audit');
  });
});

// ============================================================================
// executeGate() - span instrumentation
// ============================================================================

describe('executeGate() - agent-level span instrumentation', () => {
  it('should produce a valid execution graph', async () => {
    const orchestrator = createTestOrchestrator();
    const result = await orchestrator.executeGate(baseRequest);

    assert.ok(result.execution_graph);
    assert.strictEqual(result.execution_graph.is_valid, true);
    assert.deepStrictEqual(result.execution_graph.validation_errors, []);
    assert.strictEqual(result.status, 'ok');
  });

  it('should include gate decision in result', async () => {
    const orchestrator = createTestOrchestrator();
    const result = await orchestrator.executeGate(baseRequest);

    assert.strictEqual(result.gate.decision, 'allow');
    assert.strictEqual(result.gate.requestId, 'gate-1');
  });

  it('should produce Core -> Repo -> Agent span hierarchy', async () => {
    const orchestrator = createTestOrchestrator();
    const result = await orchestrator.executeGate(baseRequest);

    const root = result.execution_graph.root;
    assert.strictEqual(root.type, 'core');
    assert.strictEqual(root.name, 'security-core');

    for (const repo of root.children) {
      assert.strictEqual(repo.type, 'repo');
      assert.strictEqual(repo.parent_span_id, root.span_id);
      for (const agent of repo.children) {
        assert.strictEqual(agent.type, 'agent');
        assert.strictEqual(agent.parent_span_id, repo.span_id);
      }
    }
  });

  it('should emit spans for policy-engine, shield, and gate-decision', async () => {
    const orchestrator = createTestOrchestrator();
    const result = await orchestrator.executeGate(baseRequest);

    const repoNames = result.execution_graph.root.children.map(c => c.name);
    assert.ok(repoNames.includes('llm-policy-engine'), 'Must have policy-engine span');
    assert.ok(repoNames.includes('llm-shield'), 'Must have shield span');
    assert.ok(repoNames.includes('llm-security-core'), 'Must have gate-decision span');
  });

  it('should emit agent-level spans with evidence hashes', async () => {
    const orchestrator = createTestOrchestrator();
    const result = await orchestrator.executeGate(baseRequest);

    for (const repo of result.execution_graph.root.children) {
      for (const agent of repo.children) {
        assert.ok(agent.evidence, `Agent "${agent.name}" must have evidence`);
        assert.ok(agent.evidence.length > 0);
        for (const ev of agent.evidence) {
          assert.strictEqual(ev.type, 'hash');
          assert.strictEqual(ev.value.length, 64, 'SHA-256 hash must be 64 hex chars');
        }
      }
    }
  });

  it('should produce gate-decision agent span with decision attributes', async () => {
    const orchestrator = createTestOrchestrator();
    const result = await orchestrator.executeGate(baseRequest);

    const gateRepo = result.execution_graph.root.children.find(c => c.name === 'llm-security-core');
    assert.ok(gateRepo, 'Must have gate-decision repo span');
    const gateAgent = gateRepo!.children.find(c => c.name === 'gate-decision');
    assert.ok(gateAgent, 'Must have gate-decision agent span');
    assert.strictEqual(gateAgent!.attributes?.decision, 'allow');
    assert.strictEqual(gateAgent!.attributes?.policyExempt, false);
  });

  it('should attach gate-result artifact at core level', async () => {
    const orchestrator = createTestOrchestrator();
    const result = await orchestrator.executeGate(baseRequest);

    const root = result.execution_graph.root;
    assert.ok(root.artifacts, 'Core span must have artifacts');
    const gateArtifact = root.artifacts!.find(a => a.type === 'gate-result');
    assert.ok(gateArtifact, 'Must have gate-result artifact');
    assert.strictEqual(gateArtifact!.metadata?.decision, 'allow');
    assert.strictEqual(gateArtifact!.reference, 'request:gate-1');
  });

  it('should mark gate attribute on core span', async () => {
    const orchestrator = createTestOrchestrator();
    const result = await orchestrator.executeGate(baseRequest);

    assert.strictEqual(result.execution_graph.root.attributes?.gate, true);
  });

  it('should pass parentSpanId through to core span', async () => {
    const orchestrator = createTestOrchestrator();
    const result = await orchestrator.executeGate(baseRequest, { parentSpanId: 'parent-123' });

    assert.strictEqual(result.execution_graph.root.parent_span_id, 'parent-123');
  });
});

// ============================================================================
// executeGate() - deny produces full span tree
// ============================================================================

describe('executeGate() - deny/require-approval spans', () => {
  it('should produce spans for deny decisions', async () => {
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          return [{ policyId: 'block-policy', action: 'deny' }];
        }
      }
    });
    const result = await orchestrator.executeGate(baseRequest);

    assert.strictEqual(result.gate.decision, 'deny');
    assert.strictEqual(result.execution_graph.is_valid, true);

    const repoNames = result.execution_graph.root.children.map(c => c.name);
    assert.ok(repoNames.includes('llm-policy-engine'));
    assert.ok(repoNames.includes('llm-shield'));
    assert.ok(repoNames.includes('llm-security-core'));
    assert.ok(repoNames.includes('llm-incident-manager'));
  });

  it('should produce spans for require-approval decisions', async () => {
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          return [{ policyId: 'approval-policy', action: 'require-approval' }];
        }
      }
    });
    const result = await orchestrator.executeGate(baseRequest);

    assert.strictEqual(result.gate.decision, 'require-approval');
    assert.strictEqual(result.execution_graph.is_valid, true);

    const gateRepo = result.execution_graph.root.children.find(c => c.name === 'llm-security-core');
    const gateAgent = gateRepo!.children.find(c => c.name === 'gate-decision');
    assert.strictEqual(gateAgent!.attributes?.decision, 'require-approval');
  });

  it('should emit incident spans for blocking decisions', async () => {
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          return [{ policyId: 'block-policy', action: 'deny' }];
        }
      }
    });
    const result = await orchestrator.executeGate(baseRequest);

    const incidentRepo = result.execution_graph.root.children.find(c => c.name === 'llm-incident-manager');
    assert.ok(incidentRepo, 'Must have incident-manager span for deny');
    assert.ok(incidentRepo!.children.some(a => a.name === 'violation-emitter'));
  });
});

// ============================================================================
// executeGate() - failure semantics
// ============================================================================

describe('executeGate() - failure semantics', () => {
  it('should return deny gate on policy engine failure', async () => {
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate() {
          throw new Error('Policy engine unavailable');
        }
      }
    });
    const result = await orchestrator.executeGate(baseRequest);

    assert.strictEqual(result.status, 'failed');
    assert.strictEqual(result.gate.decision, 'deny');
    assert.ok(result.execution_graph);
  });

  it('should preserve execution graph on failure', async () => {
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate() {
          throw new Error('Policy engine unavailable');
        }
      }
    });
    const result = await orchestrator.executeGate(baseRequest);

    const root = result.execution_graph.root;
    assert.strictEqual(root.type, 'core');
    assert.strictEqual(root.status, 'failed');
    assert.ok(root.failure_reasons);
  });
});

// ============================================================================
// Backward compatibility
// ============================================================================

describe('gate - backward compatibility', () => {
  it('process() should still work unchanged', async () => {
    const orchestrator = createTestOrchestrator();
    const result = await orchestrator.process(baseRequest);

    assert.strictEqual(result.allowed, true);
    assert.strictEqual(result.requestId, 'gate-1');
    assert.strictEqual((result as any).decision, undefined);
  });

  it('execute() should include gate_decision field', async () => {
    const orchestrator = createTestOrchestrator();
    const result = await orchestrator.execute(baseRequest);

    assert.strictEqual(result.gate_decision, 'allow');
    assert.strictEqual(result.result?.allowed, true);
  });
});

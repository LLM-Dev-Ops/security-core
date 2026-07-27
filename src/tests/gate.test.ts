// Tests for Security-Core gate semantics
// Security is a gate, not an observer. Adapters fail closed: an unconfigured
// adapter is an error state, not a permissive mode.
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { SecurityOrchestrator } from '../services/orchestrator.js';
import { createShieldAdapter } from '../adapters/shield.js';
import { createEdgeAgentAdapter } from '../adapters/edge-agent.js';
import { createIncidentAdapter } from '../adapters/incident.js';
import { createPolicyAdapter } from '../adapters/policy.js';
import { createConfigAdapter } from '../adapters/config.js';
import { AdapterNotConfiguredError } from '../adapters/types.js';
import { createSimulatorSecurityCore } from '../sdk.js';
import { SimulatorNotPermittedError } from '../adapters/simulator.js';
import { createTestOrchestrator } from './doubles.js';
import { gateStatusCode } from '../lib.js';
import type { SecurityRequest, PolicyDecision } from '../lib.js';

const baseRequest: SecurityRequest = { id: 'gate-1', type: 'prompt', content: 'Test content' };

// ============================================================================
// gate() - explicit decision semantics
// ============================================================================

// ============================================================================
// ADR-0001 primary regression: unconfigured adapters fail closed
// ============================================================================

describe('adapters fail closed', () => {
  // This is the inversion of the pre-ADR test that constructed an orchestrator
  // with no clients at all and asserted `decision === 'allow'`.
  it('should throw at construction when no clients are configured', () => {
    assert.throws(
      () => new SecurityOrchestrator({
        shield: createShieldAdapter(),
        edgeAgent: createEdgeAgentAdapter(),
        incident: createIncidentAdapter(),
        policy: createPolicyAdapter(),
        config: createConfigAdapter()
      }),
      AdapterNotConfiguredError
    );
  });

  it('should throw from every adapter factory with no client', () => {
    assert.throws(() => createPolicyAdapter(), AdapterNotConfiguredError);
    assert.throws(() => createShieldAdapter(), AdapterNotConfiguredError);
    assert.throws(() => createEdgeAgentAdapter(), AdapterNotConfiguredError);
    assert.throws(() => createIncidentAdapter(), AdapterNotConfiguredError);
    assert.throws(() => createConfigAdapter(), AdapterNotConfiguredError);
  });

  it('should deny when the policy engine is unreachable', async () => {
    const orchestrator = createTestOrchestrator({
      policy: { async evaluate(): Promise<PolicyDecision[]> { throw new Error('connect ECONNREFUSED'); } }
    });
    const result = await orchestrator.gate(baseRequest);

    assert.strictEqual(result.decision, 'deny');
    assert.ok(result.violations);
    assert.strictEqual(result.violations[0].policy, 'policy-engine-unavailable');
    assert.strictEqual(result.violations[0].severity, 'critical');
  });

  it('should deny when the shield is unreachable rather than pass content through', async () => {
    const orchestrator = createTestOrchestrator({
      shield: { async filter() { throw new Error('shield down'); } }
    });
    const result = await orchestrator.gate(baseRequest);

    assert.strictEqual(result.decision, 'deny');
    assert.strictEqual(result.violations?.[0].policy, 'shield-unavailable');
    assert.strictEqual(result.violations?.[0].severity, 'critical');
    assert.strictEqual(result.shieldResult.filtered, '', 'unfiltered content must not be reported as filtered');
  });

  for (const [label, value] of [
    ['undefined', undefined],
    ['null', null],
    ['a string', 'allow'],
    ['an empty array', []],
    ['[{}]', [{}]],
    ['an unknown action', [{ policyId: 'p', action: 'permit' }]]
  ] as Array<[string, unknown]>) {
    it(`should deny when the policy engine resolves to ${label}`, async () => {
      const orchestrator = createTestOrchestrator({
        policy: { async evaluate() { return value as PolicyDecision[]; } }
      });
      const result = await orchestrator.gate(baseRequest);

      assert.strictEqual(result.decision, 'deny', `malformed response (${label}) must not be coerced into an allow`);
      assert.strictEqual(result.violations?.[0].policy, 'policy-engine-unavailable');
    });
  }

  it('should deny when the shield response is malformed', async () => {
    const orchestrator = createTestOrchestrator({
      shield: { async filter() { return { redactions: [] } as unknown as { filtered: string }; } }
    });
    const result = await orchestrator.gate(baseRequest);

    assert.strictEqual(result.decision, 'deny');
    assert.strictEqual(result.violations?.[0].policy, 'shield-unavailable');
  });

  it('should never produce a fabricated sim-incident id outside simulator mode', async () => {
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          return [{ policyId: 'block-policy', action: 'deny' }];
        }
      }
    });
    const result = await orchestrator.gate(baseRequest);

    assert.ok(result.incidentId);
    assert.ok(!/^sim-incident-/.test(result.incidentId!), `incidentId must not be fabricated: ${result.incidentId}`);
    assert.strictEqual(result.simulated, undefined);
  });

  it('should map an unavailable-gate denial to HTTP 403, not 200', async () => {
    const orchestrator = createTestOrchestrator({
      policy: { async evaluate(): Promise<PolicyDecision[]> { throw new Error('policy down'); } }
    });
    const result = await orchestrator.executeGate(baseRequest);

    assert.strictEqual(result.gate.decision, 'deny');
    assert.strictEqual(gateStatusCode(result.gate.decision), 403);
    assert.strictEqual(result.gate.violations?.[0].policy, 'policy-engine-unavailable');
    assert.strictEqual(result.gate.violations?.[0].severity, 'critical');
  });

  it('should report no incident id rather than invent one when the incident manager fails', async () => {
    const orchestrator = createTestOrchestrator({
      policy: { async evaluate(): Promise<PolicyDecision[]> { throw new Error('policy down'); } },
      incident: { async emit(): Promise<{ incidentId: string }> { throw new Error('incident manager down'); } }
    });
    const result = await orchestrator.gate(baseRequest);

    assert.strictEqual(result.decision, 'deny');
    assert.strictEqual(result.incidentId, undefined);
  });
});

// ============================================================================
// Simulator mode - explicit, labelled, refused in production
// ============================================================================

describe('simulator mode', () => {
  it('should stamp simulated: true on gate results', async () => {
    const result = await createSimulatorSecurityCore().gate(baseRequest);

    assert.strictEqual(result.simulated, true);
    assert.strictEqual(result.decision, 'allow');
  });

  it('should refuse to construct under NODE_ENV=production', () => {
    const previous = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    try {
      assert.throws(() => createSimulatorSecurityCore(), SimulatorNotPermittedError);
    } finally {
      if (previous === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previous;
    }
  });
});

describe('gate() - decision semantics', () => {
  it('should return explicit allow decision when a configured policy engine allows', async () => {
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          return [{ policyId: 'ok-policy', action: 'allow' }];
        }
      }
    });
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
  it('should NOT allow when policy-exempt if a policy explicitly denies', async () => {
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          return [{ policyId: 'deny-policy', action: 'deny', reason: 'Blocked' }];
        }
      }
    });
    const result = await orchestrator.gate(baseRequest, { policyExempt: true });

    assert.strictEqual(result.decision, 'deny', 'a caller-supplied flag must not overturn an explicit deny');
    assert.strictEqual(result.policyDecisions[0].action, 'deny');
    assert.strictEqual(result.policyExempt, true);
  });

  it('should NOT allow when policy-exempt if the policy engine is unavailable', async () => {
    const orchestrator = createTestOrchestrator({
      policy: { async evaluate(): Promise<PolicyDecision[]> { throw new Error('policy down'); } }
    });
    const result = await orchestrator.gate(baseRequest, { policyExempt: true });

    assert.strictEqual(result.decision, 'deny');
  });

  it('should downgrade non-deny decisions and preserve the audit trail', async () => {
    const orchestrator = createTestOrchestrator({
      policy: {
        async evaluate(): Promise<PolicyDecision[]> {
          return [{ policyId: 'approval-policy', action: 'require-approval', reason: 'Needs review' }];
        }
      }
    });
    const result = await orchestrator.gate(baseRequest, { policyExempt: true });

    assert.strictEqual(result.decision, 'allow');
    assert.strictEqual(result.policyDecisions[0].action, 'allow');
    assert.ok(result.policyDecisions[0].reason?.includes('policy-exempt'));
    assert.ok(result.policyDecisions[0].reason?.includes('original: require-approval'));
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

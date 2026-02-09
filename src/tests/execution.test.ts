// Tests for execution span instrumentation (agentics-execution-engine)
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { SecurityOrchestrator } from '../services/orchestrator.js';
import { createShieldAdapter } from '../adapters/shield.js';
import { createEdgeAgentAdapter } from '../adapters/edge-agent.js';
import { createIncidentAdapter } from '../adapters/incident.js';
import { createPolicyAdapter } from '../adapters/policy.js';
import { createConfigAdapter } from '../adapters/config.js';
import { validateExecutionGraph, buildExecutionGraph, createSpan } from '../execution/span.js';
import type { SecurityRequest } from '../lib.js';
import type { ExecutionSpan } from '../execution/types.js';

function createTestOrchestrator() {
  return new SecurityOrchestrator({
    shield: createShieldAdapter(),
    edgeAgent: createEdgeAgentAdapter(),
    incident: createIncidentAdapter(),
    policy: createPolicyAdapter(),
    config: createConfigAdapter()
  });
}

describe('ExecutionGraph - execute()', () => {
  it('should return a CoreExecutionResult with valid execution graph', async () => {
    const orchestrator = createTestOrchestrator();
    const request: SecurityRequest = { id: 'exec-1', type: 'prompt', content: 'Hello world' };
    const execResult = await orchestrator.execute(request);

    assert.ok(execResult.execution_graph);
    assert.ok(execResult.core_span_id);
    assert.strictEqual(execResult.status, 'ok');
    assert.ok(execResult.result);
    assert.strictEqual(execResult.result.requestId, 'exec-1');
    assert.strictEqual(execResult.result.allowed, true);
  });

  it('should produce hierarchical Core -> Repo -> Agent span structure', async () => {
    const orchestrator = createTestOrchestrator();
    const request: SecurityRequest = { id: 'exec-2', type: 'prompt', content: 'Test' };
    const execResult = await orchestrator.execute(request);

    const root = execResult.execution_graph.root;

    // Root is a core span
    assert.strictEqual(root.type, 'core');
    assert.strictEqual(root.name, 'security-core');

    // Must have repo-level children
    assert.ok(root.children.length > 0, 'Core span must have repo children');
    for (const repo of root.children) {
      assert.strictEqual(repo.type, 'repo');
      assert.strictEqual(repo.parent_span_id, root.span_id);

      // Each repo must have agent-level children
      assert.ok(repo.children.length > 0, `Repo "${repo.name}" must have agent children`);
      for (const agent of repo.children) {
        assert.strictEqual(agent.type, 'agent');
        assert.strictEqual(agent.parent_span_id, repo.span_id);
      }
    }
  });

  it('should emit spans for all invoked repos', async () => {
    const orchestrator = createTestOrchestrator();
    const request: SecurityRequest = { id: 'exec-3', type: 'prompt', content: 'Test' };
    const execResult = await orchestrator.execute(request);

    const repoNames = execResult.execution_graph.root.children.map(c => c.name);

    // In simulator mode with allow decision: policy-engine, shield, edge-agent
    assert.ok(repoNames.includes('llm-policy-engine'), 'Must have llm-policy-engine span');
    assert.ok(repoNames.includes('llm-shield'), 'Must have llm-shield span');
    assert.ok(repoNames.includes('llm-edge-agent'), 'Must have llm-edge-agent span');
  });

  it('should pass parent_span_id from caller', async () => {
    const orchestrator = createTestOrchestrator();
    const request: SecurityRequest = { id: 'exec-4', type: 'prompt', content: 'Test' };
    const parentId = 'external-parent-span-123';
    const execResult = await orchestrator.execute(request, parentId);

    assert.strictEqual(execResult.execution_graph.root.parent_span_id, parentId);
  });

  it('should have valid execution graph (is_valid = true)', async () => {
    const orchestrator = createTestOrchestrator();
    const request: SecurityRequest = { id: 'exec-5', type: 'prompt', content: 'Test' };
    const execResult = await orchestrator.execute(request);

    assert.strictEqual(execResult.execution_graph.is_valid, true);
    assert.deepStrictEqual(execResult.execution_graph.validation_errors, []);
  });

  it('should have correct span_count and depth', async () => {
    const orchestrator = createTestOrchestrator();
    const request: SecurityRequest = { id: 'exec-6', type: 'prompt', content: 'Test' };
    const execResult = await orchestrator.execute(request);

    // depth: core(1) -> repo(2) -> agent(3) = 3
    assert.strictEqual(execResult.execution_graph.depth, 3);
    // span_count: 1 core + N repos + N agents
    assert.ok(execResult.execution_graph.span_count >= 7, `Expected at least 7 spans, got ${execResult.execution_graph.span_count}`);
  });

  it('should attach evidence at agent level with hashes', async () => {
    const orchestrator = createTestOrchestrator();
    const request: SecurityRequest = { id: 'exec-7', type: 'prompt', content: 'Test' };
    const execResult = await orchestrator.execute(request);

    for (const repo of execResult.execution_graph.root.children) {
      for (const agent of repo.children) {
        assert.ok(agent.evidence, `Agent "${agent.name}" must have evidence`);
        assert.ok(agent.evidence.length > 0);
        for (const ev of agent.evidence) {
          assert.strictEqual(ev.type, 'hash');
          assert.ok(ev.value.length === 64, 'SHA-256 hash must be 64 hex chars');
          assert.ok(ev.id, 'Evidence must have stable identifier');
        }
      }
    }
  });

  it('should attach SecurityResult artifact at core level', async () => {
    const orchestrator = createTestOrchestrator();
    const request: SecurityRequest = { id: 'exec-8', type: 'prompt', content: 'Test' };
    const execResult = await orchestrator.execute(request);

    const root = execResult.execution_graph.root;
    assert.ok(root.artifacts, 'Core span must have artifacts');
    assert.ok(root.artifacts.length > 0);
    const resultArtifact = root.artifacts.find(a => a.type === 'security-result');
    assert.ok(resultArtifact, 'Must have security-result artifact');
    assert.strictEqual(resultArtifact!.reference, 'request:exec-8');
  });

  it('should record start_time and end_time on all spans', async () => {
    const orchestrator = createTestOrchestrator();
    const request: SecurityRequest = { id: 'exec-9', type: 'prompt', content: 'Test' };
    const execResult = await orchestrator.execute(request);

    function checkTimestamps(span: ExecutionSpan) {
      assert.ok(span.start_time, `Span "${span.name}" must have start_time`);
      assert.ok(span.end_time, `Span "${span.name}" must have end_time`);
      assert.ok(new Date(span.start_time).getTime() > 0, 'start_time must be valid ISO date');
      assert.ok(new Date(span.end_time).getTime() > 0, 'end_time must be valid ISO date');
      for (const child of span.children) {
        checkTimestamps(child);
      }
    }
    checkTimestamps(execResult.execution_graph.root);
  });

  it('should be JSON-serializable without loss', async () => {
    const orchestrator = createTestOrchestrator();
    const request: SecurityRequest = { id: 'exec-10', type: 'prompt', content: 'Test' };
    const execResult = await orchestrator.execute(request);

    const serialized = JSON.stringify(execResult);
    const deserialized = JSON.parse(serialized);

    assert.strictEqual(deserialized.status, execResult.status);
    assert.strictEqual(deserialized.core_span_id, execResult.core_span_id);
    assert.strictEqual(deserialized.execution_graph.is_valid, true);
    assert.strictEqual(deserialized.execution_graph.root.type, 'core');
    assert.ok(deserialized.execution_graph.root.children.length > 0);
  });
});

describe('ExecutionGraph - failure semantics', () => {
  it('should handle repo invocation errors and include failed spans', async () => {
    const failingPolicyAdapter = {
      async evaluate() {
        throw new Error('Policy engine unavailable');
      }
    };
    const orchestrator = new SecurityOrchestrator({
      shield: createShieldAdapter(),
      edgeAgent: createEdgeAgentAdapter(),
      incident: createIncidentAdapter(),
      policy: failingPolicyAdapter,
      config: createConfigAdapter()
    });

    const request: SecurityRequest = { id: 'fail-1', type: 'prompt', content: 'Test' };
    const execResult = await orchestrator.execute(request);

    assert.strictEqual(execResult.status, 'failed');
    assert.strictEqual(execResult.result, undefined);

    // Graph is still returned on failure
    assert.ok(execResult.execution_graph);
    const root = execResult.execution_graph.root;
    assert.strictEqual(root.status, 'failed');
    assert.ok(root.failure_reasons);
    assert.ok(root.failure_reasons.some(r => r.includes('Policy engine unavailable')));

    // Failed repo span should exist
    const failedRepo = root.children.find(c => c.name === 'llm-policy-engine');
    assert.ok(failedRepo, 'Failed repo span must still be present');
    assert.strictEqual(failedRepo!.status, 'failed');
  });

  it('should return execution graph even on total failure', async () => {
    const failingOrchestrator = new SecurityOrchestrator({
      shield: createShieldAdapter(),
      edgeAgent: createEdgeAgentAdapter(),
      incident: createIncidentAdapter(),
      policy: { async evaluate() { throw new Error('total failure'); } },
      config: createConfigAdapter()
    });

    const request: SecurityRequest = { id: 'fail-2', type: 'prompt', content: 'Test' };
    const execResult = await failingOrchestrator.execute(request);

    assert.ok(execResult.execution_graph, 'Execution graph must be returned on total failure');
    assert.strictEqual(execResult.execution_graph.root.type, 'core');
  });
});

describe('ExecutionGraph - validation', () => {
  it('should detect missing repo spans', () => {
    const coreSpan = createSpan({ type: 'core', name: 'test-core', parent_span_id: null });
    coreSpan.end_time = new Date().toISOString();

    const errors = validateExecutionGraph(coreSpan);
    assert.ok(errors.includes('No repo-level child spans exist'));
  });

  it('should detect repo with no agent spans', () => {
    const coreSpan = createSpan({ type: 'core', name: 'test-core', parent_span_id: null });
    const repoSpan = createSpan({ type: 'repo', name: 'test-repo', parent_span_id: coreSpan.span_id });
    repoSpan.end_time = new Date().toISOString();
    coreSpan.children.push(repoSpan);
    coreSpan.end_time = new Date().toISOString();

    const errors = validateExecutionGraph(coreSpan);
    assert.ok(errors.some(e => e.includes('test-repo') && e.includes('zero spans')));
  });

  it('should detect parent_span_id mismatch', () => {
    const coreSpan = createSpan({ type: 'core', name: 'test-core', parent_span_id: null });
    const repoSpan = createSpan({ type: 'repo', name: 'test-repo', parent_span_id: 'wrong-id' });
    const agentSpan = createSpan({ type: 'agent', name: 'test-agent', parent_span_id: repoSpan.span_id });
    repoSpan.children.push(agentSpan);
    coreSpan.children.push(repoSpan);

    const errors = validateExecutionGraph(coreSpan);
    assert.ok(errors.some(e => e.includes('parent_span_id mismatch')));
  });

  it('should pass validation for correct hierarchy', () => {
    const coreSpan = createSpan({ type: 'core', name: 'test-core', parent_span_id: null });
    const repoSpan = createSpan({ type: 'repo', name: 'test-repo', parent_span_id: coreSpan.span_id });
    const agentSpan = createSpan({ type: 'agent', name: 'test-agent', parent_span_id: repoSpan.span_id });
    repoSpan.children.push(agentSpan);
    coreSpan.children.push(repoSpan);

    const errors = validateExecutionGraph(coreSpan);
    assert.strictEqual(errors.length, 0);
  });

  it('should mark core span as failed when graph is invalid', () => {
    const coreSpan = createSpan({ type: 'core', name: 'test-core', parent_span_id: null });
    coreSpan.end_time = new Date().toISOString();

    const graph = buildExecutionGraph(coreSpan);
    assert.strictEqual(graph.is_valid, false);
    assert.strictEqual(graph.root.status, 'failed');
    assert.ok(graph.validation_errors.length > 0);
  });
});

describe('ExecutionGraph - backward compatibility', () => {
  it('process() should still work without execution graph', async () => {
    const orchestrator = createTestOrchestrator();
    const request: SecurityRequest = { id: 'compat-1', type: 'prompt', content: 'Hello world' };
    const result = await orchestrator.process(request);

    assert.strictEqual(result.allowed, true);
    assert.strictEqual(result.requestId, 'compat-1');
    // process() returns SecurityResult, not CoreExecutionResult
    assert.strictEqual((result as any).execution_graph, undefined);
  });
});

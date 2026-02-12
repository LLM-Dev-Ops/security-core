// SecurityOrchestrator: Core coordination logic for LLM-Security-Core
// Glue-level orchestration only - delegates to integrated systems
// Instrumented for agentics-execution-engine span emission

import { randomUUID } from 'node:crypto';
import type {
  SecurityRequest,
  SecurityResult,
  IncidentSignal,
  ShieldAdapter,
  EdgeAgentAdapter,
  IncidentAdapter,
  PolicyAdapter,
  ConfigAdapter,
  GateResult,
  GateDecision,
  SecurityGateOptions
} from '../lib.js';
import type {
  ExecutionSpan,
  CoreExecutionResult,
  SpanStatus
} from '../execution/types.js';
import {
  createSpan,
  finalizeSpan,
  failSpan,
  attachArtifact,
  attachEvidence,
  hashEvidence,
  buildExecutionGraph
} from '../execution/span.js';

export interface OrchestratorConfig {
  shield: ShieldAdapter;
  edgeAgent: EdgeAgentAdapter;
  incident: IncidentAdapter;
  policy: PolicyAdapter;
  config: ConfigAdapter;
}

export interface GateExecutionResult {
  execution_graph: import('../execution/types.js').ExecutionGraph;
  gate: GateResult;
  status: SpanStatus;
  core_span_id: string;
}

export class SecurityOrchestrator {
  constructor(private adapters: OrchestratorConfig) {}

  // ──────────────────────────────────────────────────────────────────────────
  // Gate: Required entry point for enterprise simulations
  // Security is a gate, not an observer. Simulations MUST NOT proceed
  // past orchestration if the gate returns deny or require-approval.
  // ──────────────────────────────────────────────────────────────────────────

  async gate(
    request: SecurityRequest,
    options: SecurityGateOptions = {}
  ): Promise<GateResult> {
    const { policyExempt = false } = options;

    // 1. ALWAYS evaluate policies via LLM-Policy-Engine (mandatory)
    let decisions = await this.adapters.policy.evaluate(request);

    // If policy-exempt, override all decisions to allow but preserve audit trail
    if (policyExempt) {
      decisions = decisions.map(d => ({
        ...d,
        action: 'allow' as const,
        reason: `policy-exempt (original: ${d.action}${d.reason ? ' - ' + d.reason : ''})`
      }));
    }

    // 2. ALWAYS filter via LLM-Shield (mandatory, unconditional)
    const shieldResult = await this.adapters.shield.filter(
      request.content,
      request.type === 'runtime' ? 'prompt' : request.type
    );

    // 3. Compute aggregate gate decision (most restrictive wins)
    const decision = this.computeGateDecision(decisions);

    // 4. Collect violations
    const violations = decisions
      .filter(d => d.action !== 'allow')
      .map(d => ({
        policy: d.policyId,
        severity: this.decisionSeverity(d.action)
      }));

    // 5. Emit incidents for deny / require-approval
    let incidentId: string | undefined;
    if (decision === 'deny' || decision === 'require-approval') {
      const severity = decision === 'deny' ? 'high' : 'medium';
      const blockingPolicy = decisions.find(d => d.action === decision)?.policyId ?? 'unknown';
      const result = await this.emitViolation(request, blockingPolicy, severity);
      incidentId = result.incidentId;
    } else if (violations.length > 0) {
      const result = await this.emitViolation(request, violations[0].policy, 'low');
      incidentId = result.incidentId;
    }

    return {
      requestId: request.id,
      decision,
      policyDecisions: decisions,
      shieldResult: { filtered: shieldResult.filtered, redactions: shieldResult.redactions ?? [] },
      violations: violations.length > 0 ? violations : undefined,
      incidentId,
      policyExempt
    };
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Instrumented gate: Full span tree for enterprise simulation gating
  // Every decision produces agent-level spans per mandate.
  // ──────────────────────────────────────────────────────────────────────────

  async executeGate(
    request: SecurityRequest,
    options: SecurityGateOptions = {}
  ): Promise<GateExecutionResult> {
    const { policyExempt = false, parentSpanId } = options;

    const coreSpan = createSpan({
      type: 'core',
      name: 'security-core',
      parent_span_id: parentSpanId ?? null,
      attributes: {
        requestId: request.id,
        requestType: request.type,
        gate: true,
        policyExempt
      }
    });

    let gateResult: GateResult | undefined;
    let status: SpanStatus = 'ok';

    try {
      gateResult = await this.gateInstrumented(request, coreSpan, policyExempt);

      const hasFailedChildren = coreSpan.children.some(c => c.status === 'failed');
      if (hasFailedChildren) {
        status = 'partial';
      }

      finalizeSpan(coreSpan, status);
    } catch (err) {
      status = 'failed';
      failSpan(coreSpan, (err as Error).message);
    }

    // Attach the GateResult as a core-level artifact
    if (gateResult) {
      attachArtifact(coreSpan, {
        id: randomUUID(),
        type: 'gate-result',
        reference: `request:${request.id}`,
        metadata: {
          decision: gateResult.decision,
          requestId: gateResult.requestId,
          policyExempt: gateResult.policyExempt
        }
      });
    }

    const graph = buildExecutionGraph(coreSpan);

    if (!graph.is_valid) {
      status = 'failed';
    }

    return {
      execution_graph: graph,
      gate: gateResult ?? {
        requestId: request.id,
        decision: 'deny',
        policyDecisions: [],
        shieldResult: { filtered: request.content, redactions: [] },
        policyExempt
      },
      status,
      core_span_id: coreSpan.span_id
    };
  }

  private async gateInstrumented(
    request: SecurityRequest,
    coreSpan: ExecutionSpan,
    policyExempt: boolean
  ): Promise<GateResult> {
    // 1. ALWAYS invoke LLM-Policy-Engine (mandatory, with span)
    let decisions = await this.invokeRepo(
      coreSpan,
      'llm-policy-engine',
      'policy-evaluator',
      () => this.adapters.policy.evaluate(request),
      { requestId: request.id, gate: true }
    );

    // If policy-exempt, override decisions but preserve audit trail
    if (policyExempt) {
      decisions = decisions.map(d => ({
        ...d,
        action: 'allow' as const,
        reason: `policy-exempt (original: ${d.action}${d.reason ? ' - ' + d.reason : ''})`
      }));
    }

    // 2. ALWAYS invoke LLM-Shield (mandatory, unconditional, with span)
    const shieldResult = await this.invokeRepo(
      coreSpan,
      'llm-shield',
      'content-filter',
      () => this.adapters.shield.filter(
        request.content,
        request.type === 'runtime' ? 'prompt' : request.type
      ),
      { mode: request.type === 'runtime' ? 'prompt' : request.type, gate: true }
    );

    // 3. Compute aggregate gate decision
    const decision = this.computeGateDecision(decisions);

    // 4. Collect violations
    const violations = decisions
      .filter(d => d.action !== 'allow')
      .map(d => ({
        policy: d.policyId,
        severity: this.decisionSeverity(d.action)
      }));

    // 5. Emit gate decision span (agent-level span recording the decision itself)
    await this.invokeRepo(
      coreSpan,
      'llm-security-core',
      'gate-decision',
      async () => ({ decision, policyExempt, violationCount: violations.length }),
      { decision, policyExempt, requestId: request.id }
    );

    // 6. Emit incidents for blocking decisions
    let incidentId: string | undefined;
    if (decision === 'deny' || decision === 'require-approval') {
      const severity = decision === 'deny' ? 'high' : 'medium';
      const blockingPolicy = decisions.find(d => d.action === decision)?.policyId ?? 'unknown';
      const incidentResult = await this.invokeRepo(
        coreSpan,
        'llm-incident-manager',
        'violation-emitter',
        () => this.emitViolation(request, blockingPolicy, severity),
        { policy: blockingPolicy, severity, gate: true }
      );
      incidentId = incidentResult.incidentId;
    } else if (violations.length > 0) {
      const incidentResult = await this.invokeRepo(
        coreSpan,
        'llm-incident-manager',
        'violation-emitter',
        () => this.emitViolation(request, violations[0].policy, 'low'),
        { policy: violations[0].policy, severity: 'low', gate: true }
      );
      incidentId = incidentResult.incidentId;
    }

    return {
      requestId: request.id,
      decision,
      policyDecisions: decisions,
      shieldResult: { filtered: shieldResult.filtered, redactions: shieldResult.redactions ?? [] },
      violations: violations.length > 0 ? violations : undefined,
      incidentId,
      policyExempt
    };
  }

  private computeGateDecision(decisions: import('../lib.js').PolicyDecision[]): GateDecision {
    // Most restrictive wins: deny > require-approval > filter/redact > allow
    if (decisions.some(d => d.action === 'deny')) return 'deny';
    if (decisions.some(d => d.action === 'require-approval')) return 'require-approval';
    return 'allow';
  }

  private decisionSeverity(action: string): 'low' | 'medium' | 'high' | 'critical' {
    switch (action) {
      case 'deny': return 'high';
      case 'require-approval': return 'medium';
      case 'filter':
      case 'redact': return 'low';
      default: return 'low';
    }
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Instrumented entry point (returns CoreExecutionResult with full graph)
  // ──────────────────────────────────────────────────────────────────────────

  async execute(
    request: SecurityRequest,
    parentSpanId?: string
  ): Promise<CoreExecutionResult> {
    const coreSpan = createSpan({
      type: 'core',
      name: 'security-core',
      parent_span_id: parentSpanId ?? null,
      attributes: { requestId: request.id, requestType: request.type }
    });

    let result: SecurityResult | undefined;
    let status: SpanStatus = 'ok';

    try {
      result = await this.processInstrumented(request, coreSpan);

      // Determine final status based on child span health
      const hasFailedChildren = coreSpan.children.some(c => c.status === 'failed');
      if (hasFailedChildren) {
        status = 'partial';
      }

      finalizeSpan(coreSpan, status);
    } catch (err) {
      status = 'failed';
      failSpan(coreSpan, (err as Error).message);
    }

    // Attach the SecurityResult as a core-level artifact
    if (result) {
      attachArtifact(coreSpan, {
        id: randomUUID(),
        type: 'security-result',
        reference: `request:${request.id}`,
        metadata: { allowed: result.allowed, requestId: result.requestId }
      });
    }

    const graph = buildExecutionGraph(coreSpan);

    // Per spec: if graph is invalid, Core status is FAILED
    if (!graph.is_valid) {
      status = 'failed';
    }

    return {
      execution_graph: graph,
      result,
      status,
      core_span_id: coreSpan.span_id,
      gate_decision: result ? (result.allowed ? 'allow' : 'deny') as GateDecision : undefined
    };
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Original entry point (backward compatible, no graph output)
  // ──────────────────────────────────────────────────────────────────────────

  async process(request: SecurityRequest): Promise<SecurityResult> {
    // 1. Evaluate policies via LLM-Policy-Engine
    const decisions = await this.adapters.policy.evaluate(request);

    // 2. Determine aggregate action (most restrictive wins)
    const denyDecision = decisions.find(d => d.action === 'deny');
    if (denyDecision) {
      await this.emitViolation(request, denyDecision.policyId, 'high');
      return { requestId: request.id, allowed: false, violations: [{ policy: denyDecision.policyId, severity: 'high' }] };
    }

    // 3. Apply filtering/redaction via LLM-Shield
    const filterDecision = decisions.find(d => d.action === 'filter' || d.action === 'redact');
    let filtered = request.content;
    let redactions: SecurityResult['redactions'] = [];

    if (filterDecision || request.type === 'prompt' || request.type === 'output') {
      const shieldResult = await this.adapters.shield.filter(request.content, request.type === 'runtime' ? 'prompt' : request.type);
      filtered = shieldResult.filtered;
      redactions = shieldResult.redactions;
    }

    // 4. Enforce runtime controls via LLM-Edge-Agent
    const primaryDecision = decisions[0] ?? { policyId: 'default', action: 'allow' as const };
    const enforcement = await this.adapters.edgeAgent.enforce(
      { ...request, content: filtered },
      primaryDecision
    );

    if (!enforcement.enforced) {
      await this.emitViolation(request, primaryDecision.policyId, 'medium');
      return { requestId: request.id, allowed: false, violations: [{ policy: primaryDecision.policyId, severity: 'medium' }] };
    }

    // 5. Check for threshold violations and emit incidents
    const violations = decisions
      .filter(d => d.action !== 'allow')
      .map(d => ({ policy: d.policyId, severity: 'low' as const }));

    let incidentId: string | undefined;
    if (violations.length > 0) {
      const result = await this.emitViolation(request, violations[0].policy, 'low');
      incidentId = result.incidentId;
    }

    return {
      requestId: request.id,
      allowed: true,
      filtered: enforcement.modifications ?? filtered,
      redactions,
      violations: violations.length > 0 ? violations : undefined,
      incidentId
    };
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Instrumented processing (span-emitting version of process)
  // ──────────────────────────────────────────────────────────────────────────

  private async processInstrumented(
    request: SecurityRequest,
    coreSpan: ExecutionSpan
  ): Promise<SecurityResult> {
    // 1. Evaluate policies via LLM-Policy-Engine
    const decisions = await this.invokeRepo(
      coreSpan,
      'llm-policy-engine',
      'policy-evaluator',
      () => this.adapters.policy.evaluate(request),
      { requestId: request.id }
    );

    // 2. Determine aggregate action (most restrictive wins)
    const denyDecision = decisions.find(d => d.action === 'deny');
    if (denyDecision) {
      const incidentResult = await this.invokeRepo(
        coreSpan,
        'llm-incident-manager',
        'violation-emitter',
        () => this.emitViolation(request, denyDecision.policyId, 'high'),
        { policy: denyDecision.policyId, severity: 'high' }
      );
      return {
        requestId: request.id,
        allowed: false,
        violations: [{ policy: denyDecision.policyId, severity: 'high' }],
        incidentId: incidentResult.incidentId
      };
    }

    // 3. Apply filtering/redaction via LLM-Shield
    const filterDecision = decisions.find(d => d.action === 'filter' || d.action === 'redact');
    let filtered = request.content;
    let redactions: SecurityResult['redactions'] = [];

    if (filterDecision || request.type === 'prompt' || request.type === 'output') {
      const shieldResult = await this.invokeRepo(
        coreSpan,
        'llm-shield',
        'content-filter',
        () => this.adapters.shield.filter(
          request.content,
          request.type === 'runtime' ? 'prompt' : request.type
        ),
        { mode: request.type === 'runtime' ? 'prompt' : request.type }
      );
      filtered = shieldResult.filtered;
      redactions = shieldResult.redactions;
    }

    // 4. Enforce runtime controls via LLM-Edge-Agent
    const primaryDecision = decisions[0] ?? { policyId: 'default', action: 'allow' as const };
    const enforcement = await this.invokeRepo(
      coreSpan,
      'llm-edge-agent',
      'runtime-enforcer',
      () => this.adapters.edgeAgent.enforce(
        { ...request, content: filtered },
        primaryDecision
      ),
      { policyId: primaryDecision.policyId, action: primaryDecision.action }
    );

    if (!enforcement.enforced) {
      const incidentResult = await this.invokeRepo(
        coreSpan,
        'llm-incident-manager',
        'violation-emitter',
        () => this.emitViolation(request, primaryDecision.policyId, 'medium'),
        { policy: primaryDecision.policyId, severity: 'medium' }
      );
      return {
        requestId: request.id,
        allowed: false,
        violations: [{ policy: primaryDecision.policyId, severity: 'medium' }],
        incidentId: incidentResult.incidentId
      };
    }

    // 5. Check for threshold violations and emit incidents
    const violations = decisions
      .filter(d => d.action !== 'allow')
      .map(d => ({ policy: d.policyId, severity: 'low' as const }));

    let incidentId: string | undefined;
    if (violations.length > 0) {
      const result = await this.invokeRepo(
        coreSpan,
        'llm-incident-manager',
        'violation-emitter',
        () => this.emitViolation(request, violations[0].policy, 'low'),
        { policy: violations[0].policy, severity: 'low' }
      );
      incidentId = result.incidentId;
    }

    return {
      requestId: request.id,
      allowed: true,
      filtered: enforcement.modifications ?? filtered,
      redactions,
      violations: violations.length > 0 ? violations : undefined,
      incidentId
    };
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Repo invocation with span tracking
  // ──────────────────────────────────────────────────────────────────────────

  private async invokeRepo<T>(
    coreSpan: ExecutionSpan,
    repoName: string,
    agentName: string,
    fn: () => Promise<T>,
    attributes?: Record<string, unknown>
  ): Promise<T> {
    const repoSpan = createSpan({
      type: 'repo',
      name: repoName,
      parent_span_id: coreSpan.span_id,
      attributes: { repo_name: repoName }
    });

    const agentSpan = createSpan({
      type: 'agent',
      name: agentName,
      parent_span_id: repoSpan.span_id,
      attributes
    });

    try {
      const result = await fn();

      // Attach machine-verifiable evidence at the agent level (lowest possible)
      attachEvidence(agentSpan, {
        id: randomUUID(),
        type: 'hash',
        value: hashEvidence(result),
        description: `${agentName} result hash`
      });

      finalizeSpan(agentSpan, 'ok');
      repoSpan.children.push(agentSpan);
      finalizeSpan(repoSpan, 'ok');
      coreSpan.children.push(repoSpan);

      return result;
    } catch (err) {
      const message = (err as Error).message;

      failSpan(agentSpan, message);
      repoSpan.children.push(agentSpan);
      failSpan(repoSpan, message);
      coreSpan.children.push(repoSpan);

      throw err;
    }
  }

  private async emitViolation(request: SecurityRequest, policy: string, severity: IncidentSignal['severity']) {
    const signal: IncidentSignal = {
      type: 'violation',
      severity,
      source: 'llm-security-core',
      details: { requestId: request.id, policy, requestType: request.type }
    };
    return this.adapters.incident.emit(signal);
  }
}

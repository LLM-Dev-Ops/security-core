// SecurityOrchestrator: Core coordination logic for LLM-Security-Core
// Glue-level orchestration only - delegates to integrated systems

import type {
  SecurityRequest,
  SecurityResult,
  IncidentSignal,
  ShieldAdapter,
  EdgeAgentAdapter,
  IncidentAdapter,
  PolicyAdapter,
  ConfigAdapter
} from '../lib.js';

export interface OrchestratorConfig {
  shield: ShieldAdapter;
  edgeAgent: EdgeAgentAdapter;
  incident: IncidentAdapter;
  policy: PolicyAdapter;
  config: ConfigAdapter;
}

export class SecurityOrchestrator {
  constructor(private adapters: OrchestratorConfig) {}

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

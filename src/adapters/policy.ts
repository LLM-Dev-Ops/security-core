// Adapter for LLM-Policy-Engine (14) - Declarative Security Policies
import type { PolicyAdapter, SecurityRequest, PolicyDecision } from '../lib.js';

export function createPolicyAdapter(policyEngine?: { evaluate: Function }): PolicyAdapter {
  return {
    async evaluate(request: SecurityRequest) {
      if (!policyEngine) {
        // Simulator mode: default allow policy
        return [{ policyId: 'default', action: 'allow' as const }];
      }
      const decisions = await policyEngine.evaluate(request);
      return decisions as PolicyDecision[];
    }
  };
}

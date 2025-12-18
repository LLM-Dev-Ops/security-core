// Adapter for LLM-Edge-Agent (8) - Runtime Protection Enforcement
import type { EdgeAgentAdapter, SecurityRequest, PolicyDecision } from '../lib.js';

export function createEdgeAgentAdapter(edgeAgent?: { enforce: Function }): EdgeAgentAdapter {
  return {
    async enforce(request: SecurityRequest, decision: PolicyDecision) {
      if (!edgeAgent) {
        // Simulator mode: honor decision without enforcement
        return { enforced: decision.action !== 'deny', modifications: undefined };
      }
      const result = await edgeAgent.enforce({ request, decision });
      return {
        enforced: result.enforced ?? true,
        modifications: result.modifications
      };
    }
  };
}

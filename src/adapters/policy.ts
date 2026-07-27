// Adapter for LLM-Policy-Engine (14) - Declarative Security Policies
import type { PolicyAdapter, SecurityRequest } from '../lib.js';
import {
  AdapterNotConfiguredError,
  validatePolicyDecisions,
  type PolicyEngineClient
} from './types.js';

export function createPolicyAdapter(policyEngine?: PolicyEngineClient): PolicyAdapter {
  if (!policyEngine) {
    throw new AdapterNotConfiguredError('createPolicyAdapter', 'PolicyEngineClient');
  }
  return {
    async evaluate(request: SecurityRequest) {
      return validatePolicyDecisions(await policyEngine.evaluate(request));
    }
  };
}

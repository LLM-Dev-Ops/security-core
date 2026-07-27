// Adapter for LLM-Edge-Agent (8) - Runtime Protection Enforcement
import type { EdgeAgentAdapter, SecurityRequest, PolicyDecision } from '../lib.js';
import {
  AdapterNotConfiguredError,
  validateEdgeAgentResponse,
  type EdgeAgentClient
} from './types.js';

export function createEdgeAgentAdapter(edgeAgent?: EdgeAgentClient): EdgeAgentAdapter {
  if (!edgeAgent) {
    throw new AdapterNotConfiguredError('createEdgeAgentAdapter', 'EdgeAgentClient');
  }
  return {
    async enforce(request: SecurityRequest, decision: PolicyDecision) {
      return validateEdgeAgentResponse(await edgeAgent.enforce({ request, decision }));
    }
  };
}

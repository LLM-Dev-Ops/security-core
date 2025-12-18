// LLM-Security-Core SDK - Unified exports for programmatic usage
export {
  // Types
  type SecurityRequest,
  type SecurityResult,
  type PolicyDecision,
  type IncidentSignal,
  type ShieldAdapter,
  type EdgeAgentAdapter,
  type IncidentAdapter,
  type PolicyAdapter,
  type ConfigAdapter,
  // Core orchestrator
  SecurityOrchestrator,
  // Handlers
  handleSecurityRequest,
  handleSecurityEvent,
  // Adapter factories
  createShieldAdapter,
  createEdgeAgentAdapter,
  createIncidentAdapter,
  createPolicyAdapter,
  createConfigAdapter
} from './lib.js';

import { SecurityOrchestrator } from './services/orchestrator.js';
import { createShieldAdapter } from './adapters/shield.js';
import { createEdgeAgentAdapter } from './adapters/edge-agent.js';
import { createIncidentAdapter } from './adapters/incident.js';
import { createPolicyAdapter } from './adapters/policy.js';
import { createConfigAdapter } from './adapters/config.js';
import { initializeOrchestrator } from './handlers/security.js';

// Convenience factory for creating a fully configured orchestrator
export interface SDKConfig {
  shield?: { filter: Function };
  edgeAgent?: { enforce: Function };
  incidentManager?: { emit: Function };
  policyEngine?: { evaluate: Function };
  configManager?: { get: Function; getSecret: Function };
}

export function createSecurityCore(config: SDKConfig = {}): SecurityOrchestrator {
  const adapters = {
    shield: createShieldAdapter(config.shield),
    edgeAgent: createEdgeAgentAdapter(config.edgeAgent),
    incident: createIncidentAdapter(config.incidentManager),
    policy: createPolicyAdapter(config.policyEngine),
    config: createConfigAdapter(config.configManager)
  };
  initializeOrchestrator(adapters);
  return new SecurityOrchestrator(adapters);
}

// Default export for simple usage
export default createSecurityCore;

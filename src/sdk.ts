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
  // Gate types (enterprise simulation gating)
  type GateDecision,
  type GateResult,
  type SecurityGateOptions,
  type GateExecutionResult,
  // Execution span types
  type SpanType,
  type SpanStatus,
  type ExecutionSpan,
  type ExecutionArtifact,
  type EvidenceReference,
  type ExecutionGraph,
  type CoreExecutionResult,
  // Core orchestrator
  SecurityOrchestrator,
  // Handlers
  handleSecurityRequest,
  handleSecurityEvent,
  handleSecurityGate,
  // Adapter factories
  createShieldAdapter,
  createEdgeAgentAdapter,
  createIncidentAdapter,
  createPolicyAdapter,
  createConfigAdapter,
  // Execution span utilities
  createSpan,
  finalizeSpan,
  failSpan,
  attachArtifact,
  attachEvidence,
  hashEvidence,
  validateExecutionGraph,
  buildExecutionGraph
} from './lib.js';

import { SecurityOrchestrator } from './services/orchestrator.js';
import { createShieldAdapter } from './adapters/shield.js';
import { createEdgeAgentAdapter } from './adapters/edge-agent.js';
import { createIncidentAdapter } from './adapters/incident.js';
import { createPolicyAdapter } from './adapters/policy.js';
import { createConfigAdapter } from './adapters/config.js';
import { initializeOrchestrator } from './handlers/security.js';
import {
  assertSimulatorPermitted,
  simulatorShield,
  simulatorEdgeAgent,
  simulatorIncidentManager,
  simulatorPolicyEngine,
  simulatorConfigManager
} from './adapters/simulator.js';
import type {
  ShieldClient,
  EdgeAgentClient,
  IncidentManagerClient,
  PolicyEngineClient,
  ConfigManagerClient
} from './adapters/types.js';

export type {
  ShieldClient,
  EdgeAgentClient,
  IncidentManagerClient,
  PolicyEngineClient,
  ConfigManagerClient
};

/**
 * Every client is required. Adapters fail closed, so a missing client is a
 * construction-time error rather than a silent permissive default.
 */
export interface SDKConfig {
  shield: ShieldClient;
  edgeAgent: EdgeAgentClient;
  incidentManager: IncidentManagerClient;
  policyEngine: PolicyEngineClient;
  configManager: ConfigManagerClient;
}

export function createSecurityCore(config: SDKConfig): SecurityOrchestrator {
  const adapters = {
    shield: createShieldAdapter(config?.shield),
    edgeAgent: createEdgeAgentAdapter(config?.edgeAgent),
    incident: createIncidentAdapter(config?.incidentManager),
    policy: createPolicyAdapter(config?.policyEngine),
    config: createConfigAdapter(config?.configManager)
  };
  initializeOrchestrator(adapters);
  return new SecurityOrchestrator(adapters);
}

/**
 * Explicit, opt-in pass-through core for local development. Results carry
 * `simulated: true` and construction is refused under NODE_ENV=production.
 */
export function createSimulatorSecurityCore(): SecurityOrchestrator {
  assertSimulatorPermitted();
  const adapters = {
    shield: createShieldAdapter(simulatorShield),
    edgeAgent: createEdgeAgentAdapter(simulatorEdgeAgent),
    incident: createIncidentAdapter(simulatorIncidentManager),
    policy: createPolicyAdapter(simulatorPolicyEngine),
    config: createConfigAdapter(simulatorConfigManager),
    simulated: true
  };
  initializeOrchestrator(adapters);
  return new SecurityOrchestrator(adapters);
}

// Default export for simple usage
export default createSecurityCore;

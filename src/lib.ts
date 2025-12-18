// LLM-Security-Core: Phase-8 / Layer-3 Core Integration Bundle
// Orchestrates: LLM-Shield (3), LLM-Edge-Agent (8), LLM-Incident-Manager (10),
//               LLM-Policy-Engine (14), LLM-Config-Manager (18)

// ============================================================================
// Types & Interfaces
// ============================================================================

export interface SecurityRequest {
  id: string;
  type: 'prompt' | 'output' | 'runtime';
  content: string;
  context?: Record<string, unknown>;
  metadata?: { userId?: string; sessionId?: string; timestamp?: number };
}

export interface SecurityResult {
  requestId: string;
  allowed: boolean;
  filtered?: string;
  redactions?: Array<{ start: number; end: number; reason: string }>;
  violations?: Array<{ policy: string; severity: 'low' | 'medium' | 'high' | 'critical' }>;
  incidentId?: string;
}

export interface PolicyDecision {
  policyId: string;
  action: 'allow' | 'deny' | 'filter' | 'redact';
  reason?: string;
}

export interface IncidentSignal {
  type: 'violation' | 'threshold' | 'anomaly';
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  details: Record<string, unknown>;
}

// Adapter interfaces - thin contracts for integrated systems
export interface ShieldAdapter {
  filter(content: string, mode: 'prompt' | 'output'): Promise<{ filtered: string; redactions: SecurityResult['redactions'] }>;
}

export interface EdgeAgentAdapter {
  enforce(request: SecurityRequest, decision: PolicyDecision): Promise<{ enforced: boolean; modifications?: string }>;
}

export interface IncidentAdapter {
  emit(signal: IncidentSignal): Promise<{ incidentId: string }>;
}

export interface PolicyAdapter {
  evaluate(request: SecurityRequest): Promise<PolicyDecision[]>;
}

export interface ConfigAdapter {
  get<T>(key: string): Promise<T | undefined>;
  getSecret(key: string): Promise<string | undefined>;
}

// ============================================================================
// Re-exports
// ============================================================================

export { SecurityOrchestrator } from './services/orchestrator.js';
export { handleSecurityRequest, handleSecurityEvent } from './handlers/security.js';
export { createShieldAdapter } from './adapters/shield.js';
export { createEdgeAgentAdapter } from './adapters/edge-agent.js';
export { createIncidentAdapter } from './adapters/incident.js';
export { createPolicyAdapter } from './adapters/policy.js';
export { createConfigAdapter } from './adapters/config.js';

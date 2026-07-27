// Typed test doubles. Adapters fail closed, so every orchestrator under test
// wires explicit clients — there is no "no arguments" construction path.
import { randomUUID } from 'node:crypto';
import { SecurityOrchestrator } from '../services/orchestrator.js';
import { createShieldAdapter } from '../adapters/shield.js';
import { createEdgeAgentAdapter } from '../adapters/edge-agent.js';
import { createIncidentAdapter } from '../adapters/incident.js';
import { createPolicyAdapter } from '../adapters/policy.js';
import { createConfigAdapter } from '../adapters/config.js';
import type {
  PolicyEngineClient,
  ShieldClient,
  EdgeAgentClient,
  IncidentManagerClient,
  ConfigManagerClient
} from '../adapters/types.js';

export const allowPolicyEngine: PolicyEngineClient = {
  async evaluate() {
    return [{ policyId: 'test-allow', action: 'allow' as const }];
  }
};

export const passThroughShield: ShieldClient = {
  async filter({ content }) {
    return { filtered: content, redactions: [] };
  }
};

export const enforcingEdgeAgent: EdgeAgentClient = {
  async enforce({ decision }) {
    return { enforced: decision.action !== 'deny' };
  }
};

export const recordingIncidentManager: IncidentManagerClient = {
  async emit() {
    return { incidentId: `test-incident-${randomUUID()}` };
  }
};

export const emptyConfigManager: ConfigManagerClient = {
  async get() {
    return undefined;
  },
  async getSecret() {
    return undefined;
  }
};

export interface TestClients {
  policy?: PolicyEngineClient;
  shield?: ShieldClient;
  edgeAgent?: EdgeAgentClient;
  incident?: IncidentManagerClient;
  config?: ConfigManagerClient;
}

export function createTestOrchestrator(overrides: TestClients = {}): SecurityOrchestrator {
  return new SecurityOrchestrator({
    shield: createShieldAdapter(overrides.shield ?? passThroughShield),
    edgeAgent: createEdgeAgentAdapter(overrides.edgeAgent ?? enforcingEdgeAgent),
    incident: createIncidentAdapter(overrides.incident ?? recordingIncidentManager),
    policy: createPolicyAdapter(overrides.policy ?? allowPolicyEngine),
    config: createConfigAdapter(overrides.config ?? emptyConfigManager)
  });
}

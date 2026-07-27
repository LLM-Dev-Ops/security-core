// Explicit, opt-in simulator clients for local development.
//
// Pass-through behaviour lives here and nowhere else. It is never the fallback
// of a production factory: silence is not consent to run unprotected. Results
// produced through this entrypoint carry `simulated: true`, and construction is
// refused under NODE_ENV=production.

import type { SecurityRequest, PolicyDecision, IncidentSignal } from '../lib.js';
import type {
  ShieldClient,
  ShieldFilterRequest,
  EdgeAgentClient,
  EdgeAgentEnforceRequest,
  IncidentManagerClient,
  PolicyEngineClient,
  ConfigManagerClient
} from './types.js';

export class SimulatorNotPermittedError extends Error {
  constructor() {
    super(
      'createSimulatorSecurityCore() refuses to construct under NODE_ENV=production. ' +
      'Simulator mode is a local development aid, not a deployment configuration.'
    );
    this.name = 'SimulatorNotPermittedError';
  }
}

export const simulatorPolicyEngine: PolicyEngineClient = {
  async evaluate(_request: SecurityRequest): Promise<PolicyDecision[]> {
    return [{ policyId: 'simulator-default', action: 'allow', reason: 'simulator: no policy engine configured' }];
  }
};

export const simulatorShield: ShieldClient = {
  async filter({ content }: ShieldFilterRequest) {
    return { filtered: content, redactions: [] };
  }
};

export const simulatorEdgeAgent: EdgeAgentClient = {
  async enforce({ decision }: EdgeAgentEnforceRequest) {
    return { enforced: decision.action !== 'deny' };
  }
};

export const simulatorIncidentManager: IncidentManagerClient = {
  async emit(_signal: IncidentSignal) {
    return { incidentId: `sim-incident-${Date.now()}` };
  }
};

export const simulatorConfigManager: ConfigManagerClient = {
  async get(_key: string) {
    return undefined;
  },
  async getSecret(_key: string) {
    return undefined;
  }
};

export function assertSimulatorPermitted(): void {
  if (process.env.NODE_ENV === 'production') {
    throw new SimulatorNotPermittedError();
  }
}

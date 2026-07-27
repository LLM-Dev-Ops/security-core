// Typed client contracts for the five integrated systems, plus runtime
// validation of their responses. These values cross a trust boundary: a
// compile-time type is not a runtime guarantee, so every upstream response is
// validated before it enters the typed domain. A response that fails
// validation raises, and the orchestrator converts that into a denial.

import type {
  SecurityRequest,
  PolicyDecision,
  IncidentSignal,
  SecurityResult
} from '../lib.js';

export type Redaction = NonNullable<SecurityResult['redactions']>[number];

export class AdapterNotConfiguredError extends Error {
  readonly adapter: string;

  constructor(adapter: string, clientName: string) {
    super(
      `${adapter} requires a ${clientName}. Security adapters fail closed: ` +
      `an unconfigured adapter is an error, not a mode. For local development ` +
      `use createSimulatorSecurityCore() explicitly.`
    );
    this.name = 'AdapterNotConfiguredError';
    this.adapter = adapter;
  }
}

export class UpstreamResponseError extends Error {
  readonly upstream: string;

  constructor(upstream: string, detail: string) {
    super(`${upstream} returned a malformed response: ${detail}`);
    this.name = 'UpstreamResponseError';
    this.upstream = upstream;
  }
}

// ---------------------------------------------------------------------------
// Client interfaces
// ---------------------------------------------------------------------------

export interface ShieldFilterRequest {
  content: string;
  mode: 'prompt' | 'output';
}

export interface ShieldFilterResponse {
  filtered: string;
  redactions?: Redaction[];
}

export interface ShieldClient {
  filter(input: ShieldFilterRequest): Promise<ShieldFilterResponse>;
}

export interface EdgeAgentEnforceRequest {
  request: SecurityRequest;
  decision: PolicyDecision;
}

export interface EdgeAgentEnforceResponse {
  enforced: boolean;
  modifications?: string;
}

export interface EdgeAgentClient {
  enforce(input: EdgeAgentEnforceRequest): Promise<EdgeAgentEnforceResponse>;
}

export interface IncidentEmitResponse {
  incidentId: string;
}

export interface IncidentManagerClient {
  emit(signal: IncidentSignal): Promise<IncidentEmitResponse>;
}

export interface PolicyEngineClient {
  evaluate(request: SecurityRequest): Promise<PolicyDecision[]>;
}

export interface ConfigManagerClient {
  get(key: string): Promise<unknown>;
  getSecret(key: string): Promise<string | undefined>;
}

// ---------------------------------------------------------------------------
// Runtime validators
// ---------------------------------------------------------------------------

const POLICY_ACTIONS: ReadonlyArray<PolicyDecision['action']> = [
  'allow', 'deny', 'filter', 'redact', 'require-approval'
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function validatePolicyDecisions(value: unknown): PolicyDecision[] {
  if (!Array.isArray(value)) {
    throw new UpstreamResponseError('llm-policy-engine', 'evaluate() must resolve to an array');
  }
  // An empty decision set is not an allow: the gate would have nothing to
  // derive a permit from, which is the fail-open shape this ADR removes.
  if (value.length === 0) {
    throw new UpstreamResponseError('llm-policy-engine', 'evaluate() resolved to zero decisions');
  }

  return value.map((entry, index) => {
    if (!isRecord(entry)) {
      throw new UpstreamResponseError('llm-policy-engine', `decision[${index}] is not an object`);
    }
    const { policyId, action, reason } = entry;
    if (typeof policyId !== 'string' || policyId.length === 0) {
      throw new UpstreamResponseError('llm-policy-engine', `decision[${index}].policyId is not a non-empty string`);
    }
    if (typeof action !== 'string' || !POLICY_ACTIONS.includes(action as PolicyDecision['action'])) {
      throw new UpstreamResponseError('llm-policy-engine', `decision[${index}].action is not a known action`);
    }
    if (reason !== undefined && typeof reason !== 'string') {
      throw new UpstreamResponseError('llm-policy-engine', `decision[${index}].reason is not a string`);
    }
    return { policyId, action: action as PolicyDecision['action'], reason };
  });
}

function validateRedactions(upstream: string, value: unknown): Redaction[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    throw new UpstreamResponseError(upstream, 'redactions is not an array');
  }
  return value.map((entry, index) => {
    if (!isRecord(entry)) {
      throw new UpstreamResponseError(upstream, `redactions[${index}] is not an object`);
    }
    const { start, end, reason } = entry;
    if (typeof start !== 'number' || !Number.isFinite(start)) {
      throw new UpstreamResponseError(upstream, `redactions[${index}].start is not a finite number`);
    }
    if (typeof end !== 'number' || !Number.isFinite(end)) {
      throw new UpstreamResponseError(upstream, `redactions[${index}].end is not a finite number`);
    }
    if (typeof reason !== 'string') {
      throw new UpstreamResponseError(upstream, `redactions[${index}].reason is not a string`);
    }
    return { start, end, reason };
  });
}

export function validateShieldResponse(value: unknown): { filtered: string; redactions: Redaction[] } {
  if (!isRecord(value)) {
    throw new UpstreamResponseError('llm-shield', 'filter() must resolve to an object');
  }
  if (typeof value.filtered !== 'string') {
    throw new UpstreamResponseError('llm-shield', 'filtered is not a string');
  }
  return { filtered: value.filtered, redactions: validateRedactions('llm-shield', value.redactions) };
}

export function validateEdgeAgentResponse(value: unknown): EdgeAgentEnforceResponse {
  if (!isRecord(value)) {
    throw new UpstreamResponseError('llm-edge-agent', 'enforce() must resolve to an object');
  }
  // Never defaulted to true: an absent field must not assert enforcement that
  // may not have happened.
  if (typeof value.enforced !== 'boolean') {
    throw new UpstreamResponseError('llm-edge-agent', 'enforced is not a boolean');
  }
  if (value.modifications !== undefined && typeof value.modifications !== 'string') {
    throw new UpstreamResponseError('llm-edge-agent', 'modifications is not a string');
  }
  return { enforced: value.enforced, modifications: value.modifications as string | undefined };
}

export function validateIncidentResponse(value: unknown): IncidentEmitResponse {
  if (!isRecord(value)) {
    throw new UpstreamResponseError('llm-incident-manager', 'emit() must resolve to an object');
  }
  if (typeof value.incidentId !== 'string' || value.incidentId.length === 0) {
    throw new UpstreamResponseError('llm-incident-manager', 'incidentId is not a non-empty string');
  }
  return { incidentId: value.incidentId };
}

export function validateSecret(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') {
    throw new UpstreamResponseError('llm-config-manager', 'getSecret() did not resolve to a string');
  }
  return value;
}

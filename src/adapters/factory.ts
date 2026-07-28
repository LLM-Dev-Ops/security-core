/**
 * Assembles the five clients createSecurityCore() requires from environment
 * configuration.
 *
 * There is no default URL and no fallback to the simulator. A security-core
 * that cannot reach its policy authority must refuse to start rather than boot
 * into a state where it cannot evaluate — the ADR-0001 fail-closed rule applied
 * at the process level rather than the adapter level.
 */

import type { SDKConfig } from '../sdk.js';
import { DEFAULT_UPSTREAM_TIMEOUT_MS, type HttpClientOptions } from './http/client.js';
import { createHttpPolicyEngineClient } from './http/policy.js';
import { createHttpShieldClient } from './http/shield.js';
import { createHttpEdgeAgentClient } from './http/edge-agent.js';
import { createHttpIncidentClient } from './http/incident.js';
import { createHttpConfigManagerClient, type ConfigManagerPaths } from './http/config.js';

export interface UpstreamPaths {
  policyEvaluate?: string;
  shieldFilter?: string;
  edgeAgentEnforce?: string;
  incidentEmit?: string;
  configManager: ConfigManagerPaths;
}

export interface UpstreamConfig {
  policyEngineUrl: string;
  shieldUrl: string;
  edgeAgentUrl: string;
  incidentManagerUrl: string;
  configManagerUrl: string;
  timeoutMs: number;
  paths: UpstreamPaths;
}

const REQUIRED_URLS = [
  ['policyEngineUrl', 'POLICY_ENGINE_URL'],
  ['shieldUrl', 'SHIELD_URL'],
  ['edgeAgentUrl', 'EDGE_AGENT_URL'],
  ['incidentManagerUrl', 'INCIDENT_MANAGER_URL'],
  ['configManagerUrl', 'CONFIG_MANAGER_URL'],
] as const;

export class UpstreamConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UpstreamConfigurationError';
  }
}

function readUrl(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const raw = env[name]?.trim();
  if (!raw) return undefined;
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error('unsupported protocol');
    }
  } catch {
    throw new UpstreamConfigurationError(`${name} is not a valid http(s) URL: "${raw}"`);
  }
  return raw;
}

function readTimeout(env: NodeJS.ProcessEnv): number {
  const raw = env.SECURITY_UPSTREAM_TIMEOUT_MS?.trim();
  if (!raw) return DEFAULT_UPSTREAM_TIMEOUT_MS;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new UpstreamConfigurationError(
      `SECURITY_UPSTREAM_TIMEOUT_MS must be a positive number of milliseconds, got "${raw}"`
    );
  }
  return parsed;
}

/**
 * Reads upstream configuration from the environment. Throws
 * UpstreamConfigurationError naming every absent or malformed variable.
 */
export function resolveUpstreamConfig(env: NodeJS.ProcessEnv = process.env): UpstreamConfig {
  const resolved: Partial<Record<(typeof REQUIRED_URLS)[number][0], string>> = {};
  const missing: string[] = [];

  for (const [field, envVar] of REQUIRED_URLS) {
    const value = readUrl(env, envVar);
    if (!value) {
      missing.push(envVar);
    } else {
      resolved[field] = value;
    }
  }

  if (missing.length > 0) {
    throw new UpstreamConfigurationError(
      `Refusing to start: mandatory upstream URL(s) not configured: ${missing.join(', ')}. ` +
      'security-core cannot evaluate without them and will not fall back to a simulator or an allow.'
    );
  }

  return {
    policyEngineUrl: resolved.policyEngineUrl!,
    shieldUrl: resolved.shieldUrl!,
    edgeAgentUrl: resolved.edgeAgentUrl!,
    incidentManagerUrl: resolved.incidentManagerUrl!,
    configManagerUrl: resolved.configManagerUrl!,
    timeoutMs: readTimeout(env),
    paths: {
      policyEvaluate: env.POLICY_EVALUATE_PATH?.trim() || undefined,
      shieldFilter: env.SHIELD_FILTER_PATH?.trim() || undefined,
      edgeAgentEnforce: env.EDGE_AGENT_ENFORCE_PATH?.trim() || undefined,
      incidentEmit: env.INCIDENT_EMIT_PATH?.trim() || undefined,
      configManager: {
        get: env.CONFIG_GET_PATH?.trim() || undefined,
        secret: env.CONFIG_SECRET_PATH?.trim() || undefined,
      },
    },
  };
}

/** Builds the five clients createSecurityCore() requires. */
export function createClientCollection(env: NodeJS.ProcessEnv = process.env): SDKConfig {
  const config = resolveUpstreamConfig(env);
  const opts = (baseUrl: string): HttpClientOptions => ({ baseUrl, timeoutMs: config.timeoutMs });

  return {
    policyEngine: createHttpPolicyEngineClient(opts(config.policyEngineUrl), config.paths.policyEvaluate),
    shield: createHttpShieldClient(opts(config.shieldUrl), config.paths.shieldFilter),
    edgeAgent: createHttpEdgeAgentClient(opts(config.edgeAgentUrl), config.paths.edgeAgentEnforce),
    incidentManager: createHttpIncidentClient(opts(config.incidentManagerUrl), config.paths.incidentEmit),
    configManager: createHttpConfigManagerClient(opts(config.configManagerUrl), config.paths.configManager),
  };
}

// Non-blocking HTTP router for downstream Layer 4+ services
// Fire-and-forget: dispatches to services without awaiting responses

export interface RouteTarget {
  name: string;
  url: string;
  body: Record<string, unknown>;
}

export interface RouteResult {
  accepted: true;
  routed_to: string[];
}

function dispatch(target: RouteTarget): void {
  fetch(target.url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(target.body),
    signal: AbortSignal.timeout(30_000)
  }).catch(err => {
    console.error(`[router] ${target.name} dispatch failed: ${(err as Error).message}`);
  });
}

// ---------------------------------------------------------------------------
// Service base URLs (Cloud Run)
// ---------------------------------------------------------------------------

const SHIELD_URL = process.env.LLM_SHIELD_URL
  || 'https://llm-shield-dev-1062287243982.us-central1.run.app';

const EDGE_AGENT_URL = process.env.LLM_EDGE_AGENT_URL
  || 'https://llm-edge-agent-1062287243982.us-central1.run.app';

const INCIDENT_MANAGER_URL = process.env.LLM_INCIDENT_MANAGER_URL
  || 'https://llm-incident-manager-1062287243982.us-central1.run.app';

const POLICY_ENGINE_URL = process.env.LLM_POLICY_ENGINE_URL
  || 'https://policy-engine-1062287243982.us-central1.run.app';

// ---------------------------------------------------------------------------
// POST /v1/scan — routes scan requests to Shield + Edge-Agent
// ---------------------------------------------------------------------------

export function routeScan(payload: Record<string, unknown>): RouteResult {
  const targets: RouteTarget[] = [
    {
      name: 'llm-shield',
      url: `${SHIELD_URL}/api/v1/scan`,
      body: {
        content: payload.artifacts,
        source: payload.source,
        execution_id: payload.execution_id
      }
    },
    {
      name: 'llm-edge-agent',
      url: `${EDGE_AGENT_URL}/agents/tool-invocation/execute`,
      body: {
        action: 'security_scan',
        payload
      }
    }
  ];

  for (const target of targets) {
    dispatch(target);
  }

  return {
    accepted: true,
    routed_to: targets.map(t => t.name)
  };
}

// ---------------------------------------------------------------------------
// POST /v1/audit/record — routes audit events to Incident-Manager + Policy-Engine
// ---------------------------------------------------------------------------

export function routeAuditRecord(payload: Record<string, unknown>): RouteResult {
  const targets: RouteTarget[] = [
    {
      name: 'llm-incident-manager',
      url: `${INCIDENT_MANAGER_URL}/api/v1/events`,
      body: payload
    },
    {
      name: 'llm-policy-engine',
      url: `${POLICY_ENGINE_URL}/api/evaluate`,
      body: {
        context: payload,
        action: payload.event
      }
    }
  ];

  for (const target of targets) {
    dispatch(target);
  }

  return {
    accepted: true,
    routed_to: targets.map(t => t.name)
  };
}

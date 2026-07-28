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

/**
 * Base URLs for the fan-out targets. Supplied by the caller from the single
 * resolved UpstreamConfig — there are deliberately no defaults here. The
 * previous hardcoded fallbacks pointed at `llm-shield-dev`, so a production
 * process with an unset env var silently fanned out to a dev deployment.
 */
export interface RouterUpstreams {
  shieldUrl: string;
  edgeAgentUrl: string;
  incidentManagerUrl: string;
  policyEngineUrl: string;
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
// POST /v1/scan — routes scan requests to Shield + Edge-Agent
// ---------------------------------------------------------------------------

export function routeScan(
  payload: Record<string, unknown>,
  upstreams: RouterUpstreams
): RouteResult {
  const targets: RouteTarget[] = [
    {
      name: 'llm-shield',
      url: `${upstreams.shieldUrl}/api/v1/scan`,
      body: {
        content: payload.artifacts,
        source: payload.source,
        execution_id: payload.execution_id
      }
    },
    {
      name: 'llm-edge-agent',
      url: `${upstreams.edgeAgentUrl}/agents/tool-invocation/execute`,
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

export function routeAuditRecord(
  payload: Record<string, unknown>,
  upstreams: RouterUpstreams
): RouteResult {
  const targets: RouteTarget[] = [
    {
      name: 'llm-incident-manager',
      url: `${upstreams.incidentManagerUrl}/api/v1/events`,
      body: payload
    },
    {
      name: 'llm-policy-engine',
      url: `${upstreams.policyEngineUrl}/api/evaluate`,
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

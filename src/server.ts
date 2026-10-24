// HTTP server for Cloud Run deployment
import http from 'node:http';
import { createSecurityCore, createSimulatorSecurityCore } from './sdk.js';
import { routeScan, routeAuditRecord, type RouterUpstreams } from './services/router.js';
import {
  createClientCollection,
  resolveUpstreamConfig,
  UpstreamConfigurationError
} from './adapters/factory.js';
import { gateStatusCode } from './lib.js';
import type { SecurityRequest, SecurityGateOptions } from './lib.js';
import type { SecurityOrchestrator } from './services/orchestrator.js';

export const MAX_JSON_BODY_BYTES = 64 * 1024;
const MAX_REQUEST_ID_LENGTH = 128;
const JSON_HEADERS = {
  'Content-Type': 'application/json',
  'X-Content-Type-Options': 'nosniff'
};

class HttpRequestError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: string
  ) {
    super(code);
    this.name = 'HttpRequestError';
  }
}

function buildOrchestrator(env: NodeJS.ProcessEnv): SecurityOrchestrator {
  if (env.SECURITY_CORE_SIMULATOR === '1') {
    return createSimulatorSecurityCore();
  }
  return createSecurityCore(createClientCollection(env));
}

function respondJson(res: http.ServerResponse, statusCode: number, payload: unknown): void {
  res.writeHead(statusCode, JSON_HEADERS);
  res.end(JSON.stringify(payload));
}

function respondError(res: http.ServerResponse, error: unknown): void {
  if (error instanceof HttpRequestError) {
    respondJson(res, error.statusCode, { error: error.code });
    return;
  }
  respondJson(res, 500, { error: 'internal_error' });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireBoundedIdentifier(value: unknown, field: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_REQUEST_ID_LENGTH ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new HttpRequestError(422, `invalid_${field}`);
  }
  return value;
}

function validateSecurityRequest(value: unknown): SecurityRequest {
  if (!isRecord(value)) {
    throw new HttpRequestError(422, 'invalid_request');
  }

  const id = requireBoundedIdentifier(value.id, 'request_id');
  if (value.type !== 'prompt' && value.type !== 'output' && value.type !== 'runtime') {
    throw new HttpRequestError(422, 'invalid_request_type');
  }
  if (typeof value.content !== 'string') {
    throw new HttpRequestError(422, 'invalid_content');
  }
  if (value.context !== undefined && !isRecord(value.context)) {
    throw new HttpRequestError(422, 'invalid_context');
  }
  if (value.metadata !== undefined) {
    if (!isRecord(value.metadata)) {
      throw new HttpRequestError(422, 'invalid_metadata');
    }
    if (value.metadata.userId !== undefined) {
      requireBoundedIdentifier(value.metadata.userId, 'user_id');
    }
    if (value.metadata.sessionId !== undefined) {
      requireBoundedIdentifier(value.metadata.sessionId, 'session_id');
    }
    if (
      value.metadata.timestamp !== undefined &&
      (typeof value.metadata.timestamp !== 'number' || !Number.isFinite(value.metadata.timestamp))
    ) {
      throw new HttpRequestError(422, 'invalid_timestamp');
    }
  }

  return value as unknown as SecurityRequest;
}

function validateGateOptions(value: unknown): SecurityGateOptions | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isRecord(value)) {
    throw new HttpRequestError(422, 'invalid_options');
  }
  if (value.policyExempt !== undefined && typeof value.policyExempt !== 'boolean') {
    throw new HttpRequestError(422, 'invalid_policy_exempt');
  }
  if (value.parentSpanId !== undefined) {
    requireBoundedIdentifier(value.parentSpanId, 'parent_span_id');
  }
  return value as SecurityGateOptions;
}

async function readJsonBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  const mediaType = req.headers['content-type']?.split(';', 1)[0]?.trim().toLowerCase();
  if (mediaType !== 'application/json') {
    throw new HttpRequestError(415, 'unsupported_media_type');
  }

  const contentLength = req.headers['content-length'];
  if (contentLength !== undefined) {
    const parsedLength = Number(contentLength);
    if (!Number.isSafeInteger(parsedLength) || parsedLength < 0) {
      throw new HttpRequestError(400, 'invalid_content_length');
    }
    if (parsedLength > MAX_JSON_BODY_BYTES) {
      throw new HttpRequestError(413, 'payload_too_large');
    }
  }

  const chunks: Buffer[] = [];
  let totalBytes = 0;
  let exceeded = false;

  await new Promise<void>((resolve, reject) => {
    req.on('data', (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalBytes += buffer.length;
      if (totalBytes > MAX_JSON_BODY_BYTES) {
        exceeded = true;
        return;
      }
      chunks.push(buffer);
    });
    req.on('end', resolve);
    req.on('aborted', () => reject(new HttpRequestError(400, 'request_aborted')));
    req.on('error', () => reject(new HttpRequestError(400, 'request_error')));
  });

  if (exceeded) {
    throw new HttpRequestError(413, 'payload_too_large');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpRequestError(400, 'invalid_json');
  }
  if (!isRecord(parsed)) {
    throw new HttpRequestError(422, 'invalid_json_object');
  }
  return parsed;
}

export function createSecurityServer(
  orchestrator: SecurityOrchestrator,
  upstreams?: RouterUpstreams
): http.Server {
  return http.createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      respondJson(res, 200, {
        status: 'healthy',
        service: 'security-core',
        version: process.env.npm_package_version || 'unknown'
      });
      return;
    }

    if (req.method === 'POST' && req.url === '/check') {
      try {
        const request = validateSecurityRequest(await readJsonBody(req));
        const result = await orchestrator.process(request);
        respondJson(res, 200, result);
      } catch (error) {
        respondError(res, error);
      }
      return;
    }

    if (req.method === 'POST' && req.url === '/gate') {
      try {
        const body = await readJsonBody(req);
        const request = validateSecurityRequest(body.request);
        const options = validateGateOptions(body.options);
        const result = await orchestrator.executeGate(request, options);
        respondJson(res, gateStatusCode(result.gate.decision), result);
      } catch (error) {
        respondError(res, error);
      }
      return;
    }

    if (req.method === 'POST' && req.url === '/v1/scan') {
      if (!upstreams) {
        respondFanOutUnavailable(res);
        return;
      }
      try {
        const payload = await readJsonBody(req);
        respondJson(res, 202, routeScan(payload, upstreams));
      } catch (error) {
        respondError(res, error);
      }
      return;
    }

    if (req.method === 'POST' && req.url === '/v1/audit/record') {
      if (!upstreams) {
        respondFanOutUnavailable(res);
        return;
      }
      try {
        const payload = await readJsonBody(req);
        respondJson(res, 202, routeAuditRecord(payload, upstreams));
      } catch (error) {
        respondError(res, error);
      }
      return;
    }

    respondJson(res, 404, { error: 'not_found' });
  });
}

function respondFanOutUnavailable(res: http.ServerResponse): void {
  respondJson(res, 503, { error: 'fan_out_unavailable' });
}

export function startServer(env: NodeJS.ProcessEnv = process.env): http.Server {
  const simulated = env.SECURITY_CORE_SIMULATOR === '1';
  const config = simulated ? undefined : resolveUpstreamConfig(env);
  const orchestrator = buildOrchestrator(env);
  const server = createSecurityServer(orchestrator, config);
  const port = env.PORT || 8080;

  server.listen(port, () => {
    const address = server.address();
    const boundPort = typeof address === 'object' && address !== null ? address.port : port;
    if (!config) {
      console.log(`Server listening on port ${boundPort} | SIMULATOR MODE — not a real gate`);
      return;
    }
    console.log(
      `Server listening on port ${boundPort} | policy-engine=${config.policyEngineUrl} ` +
      `shield=${config.shieldUrl} edge-agent=${config.edgeAgentUrl} ` +
      `incident-manager=${config.incidentManagerUrl} config-manager=${config.configManagerUrl} ` +
      `timeout=${config.timeoutMs}ms`
    );
  });

  return server;
}

if (require.main === module) {
  try {
    startServer();
  } catch (error) {
    if (error instanceof UpstreamConfigurationError) {
      console.error(error.message);
    } else {
      console.error(`Failed to start security-core: ${error instanceof Error ? error.message : error}`);
    }
    process.exit(1);
  }
}

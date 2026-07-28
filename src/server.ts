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

/**
 * Simulator mode is an explicit opt-in and is separately refused under
 * NODE_ENV=production by assertSimulatorPermitted(). Every other path builds
 * real HTTP clients from the environment, or refuses to start.
 */
function buildOrchestrator(env: NodeJS.ProcessEnv): SecurityOrchestrator {
  if (env.SECURITY_CORE_SIMULATOR === '1') {
    return createSimulatorSecurityCore();
  }
  return createSecurityCore(createClientCollection(env));
}

export function createSecurityServer(
  orchestrator: SecurityOrchestrator,
  upstreams?: RouterUpstreams
): http.Server {
  return http.createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'healthy',
        service: 'security-core',
        version: process.env.npm_package_version || 'unknown'
      }));
      return;
    }

    if (req.method === 'POST' && req.url === '/check') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', async () => {
        try {
          const request: SecurityRequest = JSON.parse(body);
          const result = await orchestrator.process(request);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (err) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: (err as Error).message }));
        }
      });
      return;
    }

    // Gate endpoint: required entry point for enterprise simulations
    if (req.method === 'POST' && req.url === '/gate') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', async () => {
        try {
          const { request, options } = JSON.parse(body) as {
            request: SecurityRequest;
            options?: SecurityGateOptions;
          };
          const result = await orchestrator.executeGate(request, options);
          const statusCode = gateStatusCode(result.gate.decision);
          res.writeHead(statusCode, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (err) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: (err as Error).message }));
        }
      });
      return;
    }

    // POST /v1/scan — non-blocking fan-out to Shield + Edge-Agent
    if (req.method === 'POST' && req.url === '/v1/scan') {
      if (!upstreams) {
        respondFanOutUnavailable(res);
        return;
      }
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          const result = routeScan(payload, upstreams);
          res.writeHead(202, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (err) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: (err as Error).message }));
        }
      });
      return;
    }

    // POST /v1/audit/record — non-blocking fan-out to Incident-Manager + Policy-Engine
    if (req.method === 'POST' && req.url === '/v1/audit/record') {
      if (!upstreams) {
        respondFanOutUnavailable(res);
        return;
      }
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const payload = JSON.parse(body);
          const result = routeAuditRecord(payload, upstreams);
          res.writeHead(202, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (err) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: (err as Error).message }));
        }
      });
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });
}

// Simulator mode has no resolved upstreams, and must not fan out to the real
// production services on their behalf.
function respondFanOutUnavailable(res: http.ServerResponse): void {
  res.writeHead(503, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    error: 'fan-out routes are unavailable in simulator mode: no upstreams are configured'
  }));
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

// `module: NodeNext` without `"type": "module"` in package.json emits
// CommonJS, so this is the entrypoint guard that actually applies here.
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

// HTTP server for Cloud Run deployment
import http from 'node:http';
import { createSimulatorSecurityCore } from './sdk.js';
import { routeScan, routeAuditRecord } from './services/router.js';
import { gateStatusCode } from './lib.js';
import type { SecurityRequest, SecurityGateOptions } from './lib.js';

// The server has no real peer clients wired. Rather than fall back to
// pass-through adapters, it refuses to start unless simulator mode is
// requested explicitly — misconfiguration is a loud startup failure, not a
// gate that silently allows everything.
if (process.env.SECURITY_CORE_SIMULATOR !== '1') {
  throw new Error(
    'security-core has no security clients configured. Wire real clients via ' +
    'createSecurityCore(), or set SECURITY_CORE_SIMULATOR=1 to run the ' +
    'non-production simulator explicitly.'
  );
}

const orchestrator = createSimulatorSecurityCore();

const server = http.createServer(async (req, res) => {
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
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const payload = JSON.parse(body);
        const result = routeScan(payload);
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
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const payload = JSON.parse(body);
        const result = routeAuditRecord(payload);
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

const port = process.env.PORT || 8080;
server.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});

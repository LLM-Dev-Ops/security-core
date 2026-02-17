// HTTP server for Cloud Run deployment
import http from 'node:http';
import { SecurityOrchestrator } from './services/orchestrator.js';
import { createShieldAdapter } from './adapters/shield.js';
import { createEdgeAgentAdapter } from './adapters/edge-agent.js';
import { createIncidentAdapter } from './adapters/incident.js';
import { createPolicyAdapter } from './adapters/policy.js';
import { createConfigAdapter } from './adapters/config.js';
import { routeScan, routeAuditRecord } from './services/router.js';
import type { SecurityRequest, SecurityGateOptions } from './lib.js';

const orchestrator = new SecurityOrchestrator({
  shield: createShieldAdapter(),
  edgeAgent: createEdgeAgentAdapter(),
  incident: createIncidentAdapter(),
  policy: createPolicyAdapter(),
  config: createConfigAdapter()
});

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
        const statusCode = result.gate.decision === 'allow' ? 200 : 403;
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

import assert from 'node:assert/strict';
import http from 'node:http';
import { after, before, describe, it } from 'node:test';
import { createSecurityServer, MAX_JSON_BODY_BYTES } from '../server.js';
import type { SecurityOrchestrator } from '../services/orchestrator.js';

interface HttpResult {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Record<string, unknown>;
}

describe('HTTP request boundary', () => {
  let server: http.Server;
  let port: number;
  let processCalls = 0;
  let gateCalls = 0;

  before(async () => {
    const orchestrator = {
      process: async (request: { id: string }) => {
        processCalls += 1;
        return { requestId: request.id, allowed: true };
      },
      executeGate: async (request: { id: string }) => {
        gateCalls += 1;
        return {
          requestId: request.id,
          result: { requestId: request.id, allowed: true },
          gate: {
            requestId: request.id,
            decision: 'allow',
            policyDecisions: [],
            shieldResult: { filtered: 'ok', redactions: [] },
            policyExempt: false
          },
          execution: { spans: [], status: 'completed' }
        };
      }
    } as unknown as SecurityOrchestrator;

    server = createSecurityServer(orchestrator);
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    assert(address && typeof address === 'object');
    port = address.port;
  });

  after(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
    });
  });

  async function post(
    path: string,
    body: string,
    contentType?: string
  ): Promise<HttpResult> {
    return await new Promise((resolve, reject) => {
      const headers: http.OutgoingHttpHeaders = {
        'Content-Length': Buffer.byteLength(body)
      };
      if (contentType) {
        headers['Content-Type'] = contentType;
      }

      const request = http.request({
        host: '127.0.0.1',
        port,
        path,
        method: 'POST',
        headers
      }, response => {
        let responseBody = '';
        response.on('data', chunk => {
          responseBody += chunk;
        });
        response.on('end', () => {
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: JSON.parse(responseBody) as Record<string, unknown>
          });
        });
      });
      request.on('error', reject);
      request.end(body);
    });
  }

  it('requires application/json for POST routes', async () => {
    const beforeCalls = processCalls;
    const result = await post('/check', JSON.stringify({
      id: 'request-1',
      type: 'prompt',
      content: 'safe'
    }));

    assert.equal(result.status, 415);
    assert.deepEqual(result.body, { error: 'unsupported_media_type' });
    assert.equal(result.headers['x-content-type-options'], 'nosniff');
    assert.equal(processCalls, beforeCalls);
  });

  it('rejects oversized JSON before orchestration', async () => {
    const beforeCalls = processCalls;
    const result = await post('/check', JSON.stringify({
      id: 'request-2',
      type: 'prompt',
      content: 'x'.repeat(MAX_JSON_BODY_BYTES)
    }), 'application/json');

    assert.equal(result.status, 413);
    assert.deepEqual(result.body, { error: 'payload_too_large' });
    assert.equal(processCalls, beforeCalls);
  });

  it('rejects malformed security request shapes', async () => {
    const beforeCalls = processCalls;
    const result = await post('/check', JSON.stringify({
      id: '',
      type: 'unknown',
      content: 7
    }), 'application/json');

    assert.equal(result.status, 422);
    assert.equal(result.body.error, 'invalid_request_id');
    assert.equal(processCalls, beforeCalls);
  });

  it('rejects control characters in request identifiers', async () => {
    const beforeCalls = processCalls;
    const result = await post('/check', JSON.stringify({
      id: 'request\nsmuggling',
      type: 'prompt',
      content: 'safe'
    }), 'application/json');

    assert.equal(result.status, 422);
    assert.equal(result.body.error, 'invalid_request_id');
    assert.equal(processCalls, beforeCalls);
  });

  it('does not disclose JSON parser internals', async () => {
    const result = await post('/check', '{bad', 'application/json');

    assert.equal(result.status, 400);
    assert.deepEqual(result.body, { error: 'invalid_json' });
    assert(!JSON.stringify(result.body).includes('position'));
  });

  it('accepts valid JSON media type parameters', async () => {
    const beforeCalls = processCalls;
    const result = await post('/check', JSON.stringify({
      id: 'request-3',
      type: 'prompt',
      content: 'safe',
      metadata: { timestamp: 1 }
    }), 'application/json; charset=utf-8');

    assert.equal(result.status, 200);
    assert.equal(result.body.allowed, true);
    assert.equal(processCalls, beforeCalls + 1);
  });

  it('validates gate options before execution', async () => {
    const beforeCalls = gateCalls;
    const result = await post('/gate', JSON.stringify({
      request: {
        id: 'request-4',
        type: 'prompt',
        content: 'safe'
      },
      options: { policyExempt: 'yes' }
    }), 'application/json');

    assert.equal(result.status, 422);
    assert.equal(result.body.error, 'invalid_policy_exempt');
    assert.equal(gateCalls, beforeCalls);
  });
});

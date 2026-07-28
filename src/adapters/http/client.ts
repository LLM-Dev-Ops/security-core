// Shared awaited JSON transport for the five upstream clients.
//
// Every failure mode — DNS, refused connection, timeout, non-2xx, unparseable
// body — throws. The orchestrator converts a throw into GateUnavailableError
// and therefore into a denial, so a transport failure can never become a permit.

export const DEFAULT_UPSTREAM_TIMEOUT_MS = 5000;

export interface HttpClientOptions {
  baseUrl: string;
  timeoutMs?: number;
}

export class UpstreamTransportError extends Error {
  readonly upstream: string;

  constructor(upstream: string, detail: string) {
    super(`${upstream} could not be consulted: ${detail}`);
    this.name = 'UpstreamTransportError';
    this.upstream = upstream;
  }
}

function resolveUrl(options: HttpClientOptions, path: string): URL {
  // A base URL carrying a path prefix must not have it discarded, which
  // `new URL('/x', 'https://h/prefix')` would do.
  const base = options.baseUrl.endsWith('/') ? options.baseUrl : `${options.baseUrl}/`;
  return new URL(path.replace(/^\//, ''), base);
}

async function request(
  upstream: string,
  options: HttpClientOptions,
  method: 'GET' | 'POST',
  path: string,
  payload?: unknown
): Promise<unknown> {
  const url = resolveUrl(options, path);
  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers: method === 'POST'
        ? { 'Content-Type': 'application/json', Accept: 'application/json' }
        : { Accept: 'application/json' },
      body: method === 'POST' ? JSON.stringify(payload) : undefined,
      signal: AbortSignal.timeout(options.timeoutMs ?? DEFAULT_UPSTREAM_TIMEOUT_MS)
    });
  } catch (err) {
    throw new UpstreamTransportError(upstream, (err as Error).message);
  }

  if (!res.ok) {
    throw new UpstreamTransportError(upstream, `HTTP ${res.status} from ${url.href}`);
  }

  try {
    return await res.json();
  } catch {
    throw new UpstreamTransportError(upstream, `${url.href} returned a body that is not valid JSON`);
  }
}

export function postJson(
  upstream: string,
  options: HttpClientOptions,
  path: string,
  payload: unknown
): Promise<unknown> {
  return request(upstream, options, 'POST', path, payload);
}

export function getJson(
  upstream: string,
  options: HttpClientOptions,
  path: string
): Promise<unknown> {
  return request(upstream, options, 'GET', path);
}

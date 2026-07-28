# ADR-0002: Wire Real Upstream Clients in `server.ts` and Add Reproducible Deploy Config

**Status:** Implemented
**Date:** 2026-07-27

## Context

### The service has no production boot path

ADR-0001 ("Adapters must fail closed", merged as `68b864f`, 2026-07-27) made every
`create*Adapter()` factory reject a missing client rather than silently returning a
permissive pass-through. That change is correct and is fully implemented in
`src/adapters/*.ts`. What it did **not** do is give `src/server.ts` — the actual
Cloud Run HTTP entrypoint — any way to obtain those clients.

`src/server.ts:12-20` today has exactly two branches, and both are dead in a
production Cloud Run environment:

```ts
if (process.env.SECURITY_CORE_SIMULATOR !== '1') {
  throw new Error(
    'security-core has no security clients configured. Wire real clients via ' +
    'createSecurityCore(), or set SECURITY_CORE_SIMULATOR=1 to run the ' +
    'non-production simulator explicitly.'
  );
}

const orchestrator = createSimulatorSecurityCore();
```

- **Branch (a) — `SECURITY_CORE_SIMULATOR` unset:** throws at module-import time.
  The container exits before `server.listen()`; Cloud Run crash-loops.
- **Branch (b) — `SECURITY_CORE_SIMULATOR=1`:** calls
  `createSimulatorSecurityCore()` (`src/sdk.ts:108`), which calls
  `assertSimulatorPermitted()` (`src/adapters/simulator.ts:62-66`). That throws
  `SimulatorNotPermittedError` when `NODE_ENV === 'production'`.

Branch (b) is not a usable escape hatch here, because the deploy mechanism in use
(see below) sets `NODE_ENV=production` in the runtime image by default. Both
branches therefore terminate the process. **There is currently no code path by
which this repository's `main` can boot successfully on Cloud Run.**

Note that `createSecurityCore(config: SDKConfig)` (`src/sdk.ts:92-102`) — the
seam this ADR needs — already exists and already requires all five clients.
The missing piece is purely the environment-to-client construction layer plus
the `server.ts` call site. No change to the SDK or the adapters is required.

### The live service is running stale, fail-open code

`gcloud run services describe security-core --region=us-central1` shows the serving
revision is `security-core-00004-4df`, created **2026-02-18T03:50:13Z**, from image
`us-central1-docker.pkg.dev/agentics-dev/cloud-run-source-deploy/security-core@sha256:3e34503c…`,
built **2026-02-17T06:58:17Z**.

That image predates ADR-0001 by five months. The corresponding source is commit
`6110afc` / `29a53ad` (both 2026-02-17), whose `src/server.ts` read:

```ts
const orchestrator = new SecurityOrchestrator({
  shield: createShieldAdapter(),        // no client argument
  edgeAgent: createEdgeAgentAdapter(),  // no client argument
  incident: createIncidentAdapter(),
  policy: createPolicyAdapter(),
  config: createConfigAdapter()
});
```

i.e. precisely the argument-less, pass-through-defaulting construction that
ADR-0001 was written to abolish. `GET /health` on
`https://security-core-xx7kwyd5ra-uc.a.run.app/health` returns
`{"status":"healthy","service":"security-core","version":"1.0.0"}` — so the fix is
merged in git but **the production gate is still fail-open right now**. This is the
operative risk: the repository looks fixed and the deployment is not.

The two facts compound. The live revision is unsafe, and the current `main` cannot
be deployed to replace it. Rolling forward is blocked until `server.ts` is wired.

### There is no deploy configuration in this repository

`security-core/` contains no `Dockerfile`, no `cloudbuild.yaml`, and no deploy
script (`scripts/` holds only `run-tests.mjs`). The deploy mechanism can
nevertheless be identified from the artifact path: images live in the
`cloud-run-source-deploy` Artifact Registry repository, which is the repository
`gcloud run deploy --source .` creates. The service was therefore deployed
ad-hoc from a developer workstation using Google Cloud Buildpacks, which
auto-detected `package.json` and ran `npm run build` then `npm start`.

Two consequences follow. First, buildpacks set `NODE_ENV=production` in the run
image — which is what closes branch (b) above. Second, the build is not
reproducible from the repository: nobody can recreate the serving image from a
checkout, and there is no record of which commit produced it. The only env vars
on the live revision are `FORCE_REBUILD` and a `POLICY_ENDPOINT` secret reference
that no code in this repository reads.

### Precedent: governance-core solved the identical problem

`governance-core` had the same defect — fail-closed logic implemented in the
adapters but never wired into `server.ts` — and resolved it in its own ADR-0001.
The working shape is:

- `src/adapters/factory.ts` exposes `resolveUpstreamConfig(env)`, which reads one
  env var per upstream, validates each is a well-formed `http(s)` URL, collects
  **all** missing names, and throws a single `UpstreamConfigurationError` naming
  them (`governance-core/src/adapters/factory.ts:71-103`). There is no default URL
  and no simulator fallback.
- `createAdapterCollection(env)` builds concrete `Http*Adapter` instances over
  those URLs (`factory.ts:105-117`).
- `src/server.ts:447-464` exposes `startServer(env)` = resolve config → build
  collection → construct core → listen, and `server.ts:466-477` guards the
  `require.main === module` entrypoint so a config error logs the message and
  `process.exit(1)`s rather than surfacing an opaque stack trace.
- Transport failures are never converted into successes:
  `governance-core/src/adapters/http/client.ts` maps DNS failure, connection
  refusal, timeout, non-2xx, and unparseable bodies alike to
  `{success: false}`, which the gate treats as a denial.

`governance-core/Dockerfile` is a two-stage `node:18-slim` build that is a direct
fit for this repository's toolchain (`tsc` → `dist/`, `npm start` →
`node dist/server.js`).

### Resolved upstream URLs

All five upstreams were resolved against the live `agentics-dev` /
`us-central1` project and confirmed reachable (`GET /health`, 2026-07-27):

| Adapter | Cloud Run service | URL | `/health` |
|---|---|---|---|
| policy | `policy-engine` | `https://policy-engine-xx7kwyd5ra-uc.a.run.app` | 503 `unhealthy` (see note) |
| shield | `llm-shield` | `https://llm-shield-xx7kwyd5ra-uc.a.run.app` | 200 `llm-shield` v1.0.0 |
| edgeAgent | `llm-edge-agent` | `https://llm-edge-agent-xx7kwyd5ra-uc.a.run.app` | 200 `llm-edge-agent` v0.1.0 |
| incident | `llm-incident-manager` | `https://llm-incident-manager-xx7kwyd5ra-uc.a.run.app` | 200 v1.0.1 |
| config | `llm-config-manager` | `https://llm-config-manager-xx7kwyd5ra-uc.a.run.app` | 200 `schema-truth-agent` v0.1.0 |

Selection rationale and caveats:

- **`policy-engine`, not `policy-engine-agents`.** This matches both
  `src/services/router.ts:39-40` (which already hardcodes `policy-engine` as its
  fire-and-forget target) and the live `governance-core` revision, whose
  `POLICY_ENGINE_URL` is `https://policy-engine-xx7kwyd5ra-uc.a.run.app`. Two
  independent precedents agree.
- **`llm-shield`, not `llm-shield-dev` and not `shield-agents`.**
  `router.ts:30-31` currently defaults to `llm-shield-dev`, which is a
  development deployment and is the wrong target for a production gate. The
  prod-suite name `llm-shield` is correct here and `router.ts` should be
  corrected to match as part of the same change.
- **`llm-edge-agent`, not `edge-agents` or `llm-edge-agent-phase3`.** Matches
  `router.ts:33-34`.
- **`llm-incident-manager`, not `incident-manager-agents`.** Matches
  `router.ts:36-37`.
- **`llm-config-manager` — lowest-confidence of the five.** There is no existing
  precedent in this repository, because `router.ts` never calls the config
  manager. Both `llm-config-manager` and `config-manager-agents` are live and
  healthy. `llm-config-manager` is chosen for consistency with the `llm-*`
  naming of the other four and with the adapter's own header comment
  (`src/adapters/config.ts:1`, "LLM-Config-Manager (18) — Centralized
  Configuration"). Its health response self-identifies as `schema-truth-agent`,
  which does not obviously match a config/secret role. **This choice must be
  confirmed against the upstream's API before implementation lands** — it is the
  one item in this ADR that investigation could not settle conclusively.
- **`policy-engine` currently reports itself unhealthy** (`database:
  disconnected`, `cache: disconnected`). Under the fail-closed contract this
  correctly produces denials rather than allows, so it does not block this
  change — but it is a live availability issue that must be tracked separately,
  because wiring the real client will convert today's silent fail-open into
  visible denials.

All URLs use the canonical `-xx7kwyd5ra-uc.a.run.app` hostname form returned by
`gcloud run services describe`, matching the form already used in the live
`governance-core` and `agentics-orchestration-engine` env vars. Note that
`router.ts` hardcodes the older project-number form
(`-1062287243982.us-central1.run.app`); both resolve, but the deployed
convention is the former.

## Decision

**1. `server.ts` must construct its clients from environment-driven URLs, and
must refuse to boot when any is missing.**

A new `src/adapters/factory.ts` will expose `resolveUpstreamConfig(env)` and
`createClientCollection(env)`, following the `governance-core` shape. `server.ts`
will call `createSecurityCore(createClientCollection(env))` — the existing SDK
entrypoint, unchanged. Five env vars are mandatory:
`POLICY_ENGINE_URL`, `SHIELD_URL`, `EDGE_AGENT_URL`, `INCIDENT_MANAGER_URL`,
`CONFIG_MANAGER_URL`. A missing or malformed URL raises
`UpstreamConfigurationError` naming every offending variable at once, and the
process exits non-zero.

There will be **no fallback to the simulator** and **no default URL**. The
simulator remains reachable only via an explicit `SECURITY_CORE_SIMULATOR=1`
opt-in that is additionally refused under `NODE_ENV=production` — i.e. the
existing `assertSimulatorPermitted()` guard is retained unchanged. A
security-core that cannot reach its policy authority must fail to start, not
start in a state where it cannot evaluate. This is the same reasoning as
ADR-0001, applied one layer up: silence is not consent to run unprotected, at
the process level as well as the adapter level.

Transport failures must never become successes. The HTTP clients will surface
DNS failure, connection refusal, timeout, non-2xx status, and unparseable
bodies as thrown errors, which `SecurityOrchestrator` already converts into
`GateUnavailableError` and thus into a denial
(`src/services/orchestrator.ts:44-60`).

**2. A `Dockerfile` and a `cloudbuild.yaml` must be added to this repository.**

The current serving image cannot be reproduced from a checkout and is not
traceable to a commit. The deploy must become a committed, reviewable artifact
built from a pinned `Dockerfile` and tagged with `$COMMIT_SHA`, replacing
`gcloud run deploy --source .` from a workstation.

**3. The five upstream URLs above are the values to configure**, set as Cloud Run
env vars by `cloudbuild.yaml` rather than baked into source, so that dev/staging
can point elsewhere without a code change.

## Consequences

**Positive**

- `main` becomes deployable for the first time since ADR-0001 merged, unblocking
  replacement of the stale fail-open revision.
- Misconfiguration becomes a loud startup failure naming the missing variables,
  instead of a service that boots and under-enforces.
- The ADR-0001 fail-closed guarantee finally reaches production, where it has so
  far had no effect.
- The deployed artifact becomes reproducible and attributable to a commit.
- The config surface becomes greppable: five named env vars instead of implicit
  buildpack behaviour plus hardcoded constants in `router.ts`.

**Negative / accepted costs**

- **Deploying this will surface denials that today are silent allows.** With
  `policy-engine` currently reporting `unhealthy`, requests that presently pass
  will begin to be denied. That is the correct behaviour and the entire point of
  ADR-0001, but it is a behavioural change with blast radius, and it should be
  rolled out deliberately — not as an incidental side effect of a deploy. The
  policy-engine health issue should be resolved first.
- A missing env var now takes the service down rather than degrading it. This is
  intended, and is why `cloudbuild.yaml` sets all five explicitly.
- Local `npm start` will no longer work without either the five URLs or
  `SECURITY_CORE_SIMULATOR=1` with a non-production `NODE_ENV`.
- The `llm-config-manager` choice carries residual uncertainty (see Context) and
  may need revising during implementation.

**Neutral**

- The pre-existing `POLICY_ENDPOINT` secret on the live revision is read by no
  code in this repository. It should be removed or reconciled during
  implementation, not carried forward unexamined.

## Implementation Plan

> This ADR is documentation for a subsequent implementation pass. No source file
> is modified by this ADR.

**1. Add `src/adapters/http/client.ts` — shared awaited JSON transport.**

Mirrors `governance-core/src/adapters/http/client.ts`, except that failures
*throw* rather than returning `{success: false}`, because security-core's client
interfaces (`src/adapters/types.ts:44-87`) return bare values, and the
orchestrator already catches to produce `GateUnavailableError`.

```ts
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

export async function postJson(
  upstream: string,
  options: HttpClientOptions,
  path: string,
  payload: unknown
): Promise<unknown> {
  const url = new URL(path, options.baseUrl);
  let res: Response;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(options.timeoutMs ?? DEFAULT_UPSTREAM_TIMEOUT_MS)
    });
  } catch (err) {
    // DNS, refused connection, timeout — never a success.
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
```

**2. Add `src/adapters/http/{shield,edge-agent,incident,policy,config}.ts` —
concrete implementations of the five `*Client` interfaces.**

Each returns the raw decoded body; the existing `create*Adapter()` wrappers
already run the ADR-0001 runtime validators (`validatePolicyDecisions`,
`validateShieldResponse`, …) over the result, so no validation is duplicated
here. Paths default to those `router.ts` already uses against the same services,
and are env-overridable because they have not been verified against each
upstream's contract:

```ts
export function createHttpPolicyEngineClient(o: HttpClientOptions): PolicyEngineClient {
  return {
    async evaluate(request: SecurityRequest): Promise<PolicyDecision[]> {
      // `request.action` does not exist on SecurityRequest; the action is
      // carried as `request.type`. Corrected during implementation.
      const body = await postJson('llm-policy-engine', o, POLICY_EVALUATE_PATH, {
        context: request,
        action: request.type
      });
      // Some deployments wrap the decision set in a `decisions` / `result` envelope.
      const record = body as Record<string, unknown>;
      return (record?.decisions ?? record?.result ?? body) as PolicyDecision[];
    }
  };
}

export function createHttpShieldClient(o: HttpClientOptions): ShieldClient {
  return {
    async filter(input: ShieldFilterRequest): Promise<ShieldFilterResponse> {
      return await postJson('llm-shield', o, SHIELD_FILTER_PATH, input) as ShieldFilterResponse;
    }
  };
}
```

`edge-agent`, `incident`, and `config` follow the same shape against
`EDGE_AGENT_ENFORCE_PATH`, `INCIDENT_EMIT_PATH`, and
`CONFIG_GET_PATH` / `CONFIG_SECRET_PATH` respectively. Returning the raw body
and letting the ADR-0001 validators reject it is deliberate: a malformed
upstream response must reach `UpstreamResponseError`, not be papered over here.

**3. Add `src/adapters/factory.ts` — the `resolveUpstreamConfig` equivalent.**

```ts
export interface UpstreamConfig {
  policyEngineUrl: string;
  shieldUrl: string;
  edgeAgentUrl: string;
  incidentManagerUrl: string;
  configManagerUrl: string;
  timeoutMs: number;
}

const REQUIRED_URLS = [
  ['policyEngineUrl',     'POLICY_ENGINE_URL'],
  ['shieldUrl',           'SHIELD_URL'],
  ['edgeAgentUrl',        'EDGE_AGENT_URL'],
  ['incidentManagerUrl',  'INCIDENT_MANAGER_URL'],
  ['configManagerUrl',    'CONFIG_MANAGER_URL'],
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

export function resolveUpstreamConfig(env: NodeJS.ProcessEnv = process.env): UpstreamConfig {
  const resolved: Partial<Record<(typeof REQUIRED_URLS)[number][0], string>> = {};
  const missing: string[] = [];

  for (const [field, envVar] of REQUIRED_URLS) {
    const value = readUrl(env, envVar);
    if (!value) missing.push(envVar);
    else resolved[field] = value;
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
    timeoutMs: readTimeout(env),   // SECURITY_UPSTREAM_TIMEOUT_MS, default 5000
  };
}

/** Builds the five clients `createSecurityCore()` requires. */
export function createClientCollection(env: NodeJS.ProcessEnv = process.env): SDKConfig {
  const config = resolveUpstreamConfig(env);
  const opts = (baseUrl: string): HttpClientOptions => ({ baseUrl, timeoutMs: config.timeoutMs });

  return {
    policyEngine:    createHttpPolicyEngineClient(opts(config.policyEngineUrl)),
    shield:          createHttpShieldClient(opts(config.shieldUrl)),
    edgeAgent:       createHttpEdgeAgentClient(opts(config.edgeAgentUrl)),
    incidentManager: createHttpIncidentClient(opts(config.incidentManagerUrl)),
    configManager:   createHttpConfigManagerClient(opts(config.configManagerUrl)),
  };
}
```

**4. Rewrite the boot section of `src/server.ts`.**

Replace the throwing top-level block at `src/server.ts:8-20` with a lazily-invoked
`startServer(env)`. The orchestrator must be constructed *inside* `startServer`,
not at module scope, so that importing `server.ts` from a test does not require
the environment to be configured.

```ts
import { createSecurityCore, createSimulatorSecurityCore } from './sdk.js';
import { createClientCollection, resolveUpstreamConfig, UpstreamConfigurationError } from './adapters/factory.js';

/**
 * Simulator mode is an explicit opt-in and is separately refused under
 * NODE_ENV=production by assertSimulatorPermitted(). Everything else builds
 * real HTTP clients from the environment, or refuses to start.
 */
function buildOrchestrator(env: NodeJS.ProcessEnv): SecurityOrchestrator {
  if (env.SECURITY_CORE_SIMULATOR === '1') {
    return createSimulatorSecurityCore();
  }
  return createSecurityCore(createClientCollection(env));
}

export function startServer(env: NodeJS.ProcessEnv = process.env): http.Server {
  const orchestrator = buildOrchestrator(env);
  const server = createSecurityServer(orchestrator);   // existing route table, unchanged
  const port = env.PORT || 8080;

  server.listen(port, () => {
    if (env.SECURITY_CORE_SIMULATOR === '1') {
      console.log(`Server listening on port ${port} | SIMULATOR MODE — not a real gate`);
      return;
    }
    const c = resolveUpstreamConfig(env);
    console.log(
      `Server listening on port ${port} | policy-engine=${c.policyEngineUrl} ` +
      `shield=${c.shieldUrl} edge-agent=${c.edgeAgentUrl} ` +
      `incident-manager=${c.incidentManagerUrl} config-manager=${c.configManagerUrl} ` +
      `timeout=${c.timeoutMs}ms`
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
```

**Corrected during implementation.** This ADR originally specified an ESM
entrypoint guard (`import.meta.url === …`) on the grounds that the package is
`module: NodeNext`. That is not sufficient: `package.json` has no
`"type": "module"`, so `NodeNext` emits CommonJS and `tsc` rejects
`import.meta` with TS1470. The guard is therefore `require.main === module`,
the same form governance-core uses. Switching the package to ESM was rejected
as out of scope for a deploy-unblocking change.

**5. Correct `src/services/router.ts` to share the same configuration.**

`router.ts:30-40` hardcodes four base URLs — including `llm-shield-dev`, a
development deployment — as fallbacks behind `LLM_*_URL` env vars. Drop the
hardcoded defaults and read the same `UpstreamConfig`, so there is exactly one
place a URL is configured and no path that silently targets a dev service from
production.

As implemented, `routeScan`/`routeAuditRecord` take the four base URLs as a
`RouterUpstreams` argument supplied by `startServer` from the single resolved
`UpstreamConfig`, rather than reading the environment themselves. A consequence
is that simulator mode has no upstreams to fan out to; `/v1/scan` and
`/v1/audit/record` therefore return 503 in simulator mode rather than dispatch
to the real production services on a simulator's behalf.

**6. Add `Dockerfile`** — two-stage, matching `governance-core/Dockerfile`,
which is an exact fit for this toolchain (`tsc` → `dist/`, `npm start` →
`node dist/server.js`):

```dockerfile
FROM node:18-slim AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:18-slim
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev --ignore-scripts
COPY --from=build /app/dist ./dist
ENV PORT=8080
EXPOSE 8080
CMD ["node", "dist/server.js"]
```

`--ignore-scripts` is deliberate: this repository declares five optional
`peerDependencies` (`llm-shield`, `llm-edge-agent`, …) that are not installed and
must not trigger lifecycle scripts during a security-service build.

**7. Add `cloudbuild.yaml`**, following the `sentinel`/`schema-registry` house
style (build → push → deploy → verify, `$COMMIT_SHA`-tagged) but reduced to what
a small Node service needs. Critically, it sets all five upstream env vars, so a
deploy cannot produce a revision that fails step 3's check:

```yaml
substitutions:
  _ENV: prod
  _REGION: us-central1
  _SERVICE_NAME: security-core
  _REPOSITORY: security-core

options:
  logging: CLOUD_LOGGING_ONLY
  dynamic_substitutions: true

steps:
  - name: 'gcr.io/cloud-builders/docker'
    id: 'build'
    args:
      - 'build'
      - '-t'
      - '${_REGION}-docker.pkg.dev/${PROJECT_ID}/${_REPOSITORY}/${_SERVICE_NAME}:${COMMIT_SHA}'
      - '-t'
      - '${_REGION}-docker.pkg.dev/${PROJECT_ID}/${_REPOSITORY}/${_SERVICE_NAME}:latest'
      - '--cache-from'
      - '${_REGION}-docker.pkg.dev/${PROJECT_ID}/${_REPOSITORY}/${_SERVICE_NAME}:latest'
      - '-f'
      - 'Dockerfile'
      - '.'
    timeout: 1200s

  - name: 'gcr.io/cloud-builders/docker'
    id: 'push'
    waitFor: ['build']
    args: ['push', '--all-tags', '${_REGION}-docker.pkg.dev/${PROJECT_ID}/${_REPOSITORY}/${_SERVICE_NAME}']

  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    id: 'deploy'
    waitFor: ['push']
    entrypoint: 'gcloud'
    args:
      - 'run'
      - 'deploy'
      - '${_SERVICE_NAME}'
      - '--image'
      - '${_REGION}-docker.pkg.dev/${PROJECT_ID}/${_REPOSITORY}/${_SERVICE_NAME}:${COMMIT_SHA}'
      - '--region'
      - '${_REGION}'
      - '--platform'
      - 'managed'
      - '--port'
      - '8080'
      - '--cpu'
      - '1'
      - '--memory'
      - '512Mi'
      - '--min-instances'
      - '1'
      - '--max-instances'
      - '10'
      - '--concurrency'
      - '80'
      - '--timeout'
      - '60s'
      - '--set-env-vars'
      - >-
        NODE_ENV=production,SERVICE_NAME=${_SERVICE_NAME},SERVICE_VERSION=${COMMIT_SHA},PLATFORM_ENV=${_ENV},SECURITY_UPSTREAM_TIMEOUT_MS=5000,POLICY_ENGINE_URL=https://policy-engine-xx7kwyd5ra-uc.a.run.app,SHIELD_URL=https://llm-shield-xx7kwyd5ra-uc.a.run.app,EDGE_AGENT_URL=https://llm-edge-agent-xx7kwyd5ra-uc.a.run.app,INCIDENT_MANAGER_URL=https://llm-incident-manager-xx7kwyd5ra-uc.a.run.app,CONFIG_MANAGER_URL=https://llm-config-manager-xx7kwyd5ra-uc.a.run.app
      - '--labels'
      - 'env=${_ENV},service=${_SERVICE_NAME},managed-by=cloud-build'

  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    id: 'verify'
    waitFor: ['deploy']
    entrypoint: 'bash'
    args:
      - '-c'
      - |
        set -e
        sleep 10
        SERVICE_URL=$(gcloud run services describe ${_SERVICE_NAME} \
          --region=${_REGION} --format='value(status.url)')
        CODE=$(curl -s -o /dev/null -w "%{http_code}" "$${SERVICE_URL}/health")
        [ "$${CODE}" = "200" ] || { echo "health check failed: $${CODE}"; exit 1; }
        echo "Deployed $${SERVICE_URL} at ${COMMIT_SHA}"

images:
  - '${_REGION}-docker.pkg.dev/${PROJECT_ID}/${_REPOSITORY}/${_SERVICE_NAME}:${COMMIT_SHA}'
  - '${_REGION}-docker.pkg.dev/${PROJECT_ID}/${_REPOSITORY}/${_SERVICE_NAME}:latest'

timeout: 1800s
```

`NODE_ENV=production` is set explicitly rather than inherited from buildpack
behaviour, so that `assertSimulatorPermitted()` reliably refuses simulator mode
in this environment regardless of base image.

**8. Reconcile the stray `POLICY_ENDPOINT` secret** currently bound on the live
revision. No code in this repository reads it. Either remove it or, if it is the
intended source of the policy URL, wire it via `--set-secrets
POLICY_ENGINE_URL=POLICY_ENDPOINT:latest` instead of the literal above. Do not
carry it forward unexamined.

**9. Sequencing.** Land steps 1–7 and confirm `policy-engine` is healthy
*before* deploying. Deploying a correctly fail-closed security-core against an
unhealthy policy engine will convert today's silent allows into denials; that is
correct but must be an intentional, announced rollout rather than a side effect.

## Verification

1. **Refuses to boot with no configuration.** `npm run build && node dist/server.js`
   with none of the five vars set exits non-zero and prints
   `Refusing to start: mandatory upstream URL(s) not configured: POLICY_ENGINE_URL,
   SHIELD_URL, EDGE_AGENT_URL, INCIDENT_MANAGER_URL, CONFIG_MANAGER_URL`.
2. **Names every missing variable, not just the first.** With only
   `POLICY_ENGINE_URL` set, the error lists the remaining four.
3. **Rejects malformed URLs.** `SHIELD_URL=notaurl` produces
   `SHIELD_URL is not a valid http(s) URL: "notaurl"`.
4. **Does not fall back to the simulator.** With `NODE_ENV=production` and no
   URLs set, the process exits non-zero; no request is ever served, and no
   response carries `simulated: true`.
5. **Boots with all five set.** Startup logs the five resolved URLs and the
   timeout; `GET /health` returns 200.
6. **Upstream failure is a denial, not an allow.** Point `POLICY_ENGINE_URL` at
   a closed port and `POST /gate`; expect a non-2xx gate denial citing
   `policy-engine-unavailable`, never a permit. This is the ADR-0001 property,
   asserted end-to-end through the HTTP layer for the first time.
7. **Unit tests** in `src/tests/` cover `resolveUpstreamConfig` (all-missing,
   partial, malformed, valid) and `createClientCollection`, using injected `env`
   objects rather than mutating `process.env`.
8. **Container parity.** `docker build -t security-core:local .` then
   `docker run -e PORT=8080 -e NODE_ENV=production -p 8080:8080 security-core:local`
   with no URLs exits non-zero; with all five set, `/health` returns 200. This
   confirms the check survives the image build, which the buildpack deploy never
   demonstrated.
9. **Post-deploy.** `gcloud run services describe security-core --region=us-central1`
   shows a revision whose image tag is a real `$COMMIT_SHA` in the
   `security-core` Artifact Registry repository — not `cloud-run-source-deploy` —
   and whose env vars list all five upstream URLs.

# ADR-0001: Security Adapters Must Fail Closed

**Status:** Proposed

**Date:** 2026-07-27

## Context

`llm-security-core` is documented as the "Required entry point for enterprise simulation
workflows" (`README.md:45`). Its own source comments state the contract plainly:

```ts
// src/services/orchestrator.ts:52-56
// Gate: Required entry point for enterprise simulations
// Security is a gate, not an observer. Simulations MUST NOT proceed
// past orchestration if the gate returns deny or require-approval.
```

A verification pass over `src/adapters/` found that **every adapter fails open**. When its
upstream client is absent, each one returns a permissive default rather than denying. Since
all five peer dependencies are declared optional (`package.json:23-36`,
`peerDependenciesMeta` marks `llm-shield`, `llm-edge-agent`, `llm-incident-manager`,
`llm-policy-engine`, and `llm-config-manager` all `{"optional": true}`), the unconfigured
state is not an edge case — it is the default install.

### Finding 1: every adapter returns a permissive default when unconfigured

| Adapter | File:line | Behavior with no client |
|---|---|---|
| Policy | `src/adapters/policy.ts:7-10` | returns `[{policyId: 'default', action: 'allow'}]` |
| Shield | `src/adapters/shield.ts:7-10` | returns `{filtered: content, redactions: []}` — unfiltered pass-through |
| Edge agent | `src/adapters/edge-agent.ts:7-10` | returns `{enforced: decision.action !== 'deny'}` — claims enforcement that did not occur |
| Incident | `src/adapters/incident.ts:7-10` | returns a fabricated `sim-incident-${Date.now()}` ID |
| Config | `src/adapters/config.ts:6-18` | returns `undefined` for both `get` and `getSecret` |

The policy case is the most severe:

```ts
// src/adapters/policy.ts:4-10
export function createPolicyAdapter(policyEngine?: { evaluate: Function }): PolicyAdapter {
  return {
    async evaluate(request: SecurityRequest) {
      if (!policyEngine) {
        // Simulator mode: default allow policy
        return [{ policyId: 'default', action: 'allow' as const }];
      }
```

The orchestrator's comment at `src/services/orchestrator.ts:64` reads "ALWAYS evaluate
policies via LLM-Policy-Engine (mandatory)" — but with no engine wired, line 65 receives a
synthetic unconditional allow. `computeGateDecision` then aggregates "most restrictive
wins" (`src/services/orchestrator.ts:83`) over a set containing exactly one `allow`, so the
gate returns `allow`, `violations` is empty, and no incident is emitted
(`src/services/orchestrator.ts:94-103`). A caller cannot distinguish "policy engine
evaluated this request and permitted it" from "no policy engine exists."

Shield is equally consequential: `src/adapters/shield.ts:9` returns the content verbatim
with `redactions: []`, so the "mandatory, unconditional" filtering step at
`src/services/orchestrator.ts:76-80` performs no filtering while reporting a clean result.

Edge agent actively misreports: `src/adapters/edge-agent.ts:9` returns `enforced: true`
whenever the decision was not `deny`, asserting that runtime protection was applied when no
enforcement component was ever contacted.

### Finding 2: the fabricated incident ID destroys the audit trail

`src/adapters/incident.ts:9` mints `sim-incident-${Date.now()}` and returns it as a real
`incidentId`. The orchestrator propagates this into `GateResult.incidentId`
(`src/services/orchestrator.ts:99-105`). A downstream auditor receives an incident
identifier that references nothing and was never recorded anywhere — worse than a null,
because it reads as evidence that an incident was filed.

### Finding 3: client types are `Function`-shaped, discarding type safety at the trust boundary

Every factory types its client as a bag of bare `Function`s:
`{ evaluate: Function }` (`src/adapters/policy.ts:4`), `{ filter: Function }`
(`src/adapters/shield.ts:4`), `{ enforce: Function }` (`src/adapters/edge-agent.ts:4`),
`{ emit: Function }` (`src/adapters/incident.ts:4`), `{ get: Function; getSecret: Function }`
(`src/adapters/config.ts:4`).

`Function` accepts any arity and returns `any`. The compiler therefore cannot check the
call at `src/adapters/policy.ts:11`, and the result is laundered into the typed domain by an
unchecked assertion on line 12 (`return decisions as PolicyDecision[]`). A policy engine
returning `undefined`, a string, or an object of the wrong shape passes `tsc` and fails —
or silently misbehaves — at runtime, at the exact boundary where the security decision
enters the system. The same pattern appears at `src/adapters/shield.ts:14`
(`result.redactions as SecurityResult['redactions'] ?? []`). Note that `tsconfig.json:9`
sets `"strict": true`, so this is a deliberate opt-out of the checking the project
otherwise enforces.

### Finding 4: `npm test` passes while running zero tests

The survey's claim that no `tests/` directory exists is **incorrect** — `src/tests/` holds
four files: `gate.test.ts`, `orchestrator.test.ts`, `router.test.ts`, `execution.test.ts`.
The real problem is the wiring. `package.json:13` is:

```json
"test": "node --test dist/tests/*.test.js"
```

`dist/` is gitignored (`.gitignore:2`) and absent from a fresh clone. Running `npm test`
without first running `npm run build` produces:

```
ℹ tests 0
ℹ suites 0
ℹ pass 0
ℹ fail 0
EXIT=0
```

Zero tests executed, **exit code 0**. Any CI job invoking `npm test` reports green while
verifying nothing. The glob silently matches nothing rather than erroring.

### Finding 5: the existing tests encode fail-open as correct

Worse than absent coverage, the current suite asserts the fail-open behavior is desired:

```ts
// src/tests/gate.test.ts:18-24
return new SecurityOrchestrator({
    shield: createShieldAdapter(overrides?.shield),
    edgeAgent: createEdgeAgentAdapter(),
    incident: createIncidentAdapter(),
    policy: createPolicyAdapter(overrides?.policy),
    config: createConfigAdapter()
});

// src/tests/gate.test.ts:34-41
it('should return explicit allow decision when all policies allow', async () => {
    const orchestrator = createTestOrchestrator();
    const result = await orchestrator.gate(baseRequest);
    assert.strictEqual(result.decision, 'allow');
```

`createTestOrchestrator()` with no arguments constructs an orchestrator with **no clients at
all**, and the test asserts the gate returns `allow`. The test name claims "when all
policies allow," but no policies were evaluated. This test will need to invert.

### Finding 6: `policyExempt` is a documented total bypass

`src/services/orchestrator.ts:67-74` rewrites every decision to `allow` when
`options.policyExempt` is set, including decisions that were explicitly `deny`. It preserves
the original action in a `reason` string, which is good, but it is an unauthenticated
caller-supplied flag that overrides the gate. This is out of scope for this ADR but is
recorded here as a related exposure requiring its own decision.

## Decision

Security adapters will **fail closed**. An adapter with no configured client is an error
state, not a mode.

1. **A missing required client is a construction-time error.** `createPolicyAdapter()`,
   `createShieldAdapter()`, and `createEdgeAgentAdapter()` called with no client **throw**
   immediately, rather than returning an object that later fabricates permissive results.
   Failure surfaces at wiring time, not as a silent allow during a request.

2. **When a gate cannot evaluate, it denies.** If policy evaluation cannot be performed —
   no client, upstream unreachable, malformed response — `gate()` returns
   `decision: 'deny'` with a violation of `policy: 'policy-engine-unavailable'` and
   severity `critical`. There is no code path from "cannot evaluate" to `allow`.

3. **Simulator mode becomes explicit, opt-in, and self-identifying.** Pass-through behavior
   remains available for local development, but only via an explicit
   `createSimulatorSecurityCore()` entrypoint, never as the fallback of a production
   factory. Every `GateResult` it produces carries `simulated: true`, and the orchestrator
   refuses to construct in simulator mode when `NODE_ENV === 'production'`. Silence is never
   interpreted as consent to run unprotected.

4. **Fabricated incident IDs are removed.** The incident adapter with no client throws per
   decision 1. It will never invent an identifier for an incident that was not recorded.

5. **Client types become real interfaces.** Each factory takes a declared client interface —
   `PolicyEngineClient`, `ShieldClient`, `EdgeAgentClient`, `IncidentManagerClient`,
   `ConfigManagerClient` — with typed parameters and typed return values, replacing every
   `Function`. The unchecked assertions at `src/adapters/policy.ts:12` and
   `src/adapters/shield.ts:14` are replaced by runtime validation of the upstream response
   shape, since these values cross a trust boundary and a compile-time type is not a runtime
   guarantee. A response that fails validation is a denial, not a coercion.

6. **The test suite must actually run.** `npm test` will compile first and fail loudly when
   no tests match, so a green result means tests passed rather than tests were absent.

## Consequences

**Positive.** The gate stops issuing allow decisions it did not derive. Misconfiguration
becomes a loud startup failure instead of a silent security hole that looks identical to a
clean pass. The audit trail stops containing fabricated incident IDs. Type errors at the
upstream boundary are caught by `tsc` rather than surfacing as runtime `undefined`.

**Negative.** This is a **breaking change** for every current consumer. Anyone who calls
`createSecurityCore()` with no peer dependencies installed — the arrangement `README.md:176`
and `README.md:213-214` explicitly document as supported — will now get a thrown error at
construction. The optional `peerDependenciesMeta` declarations at `package.json:30-36` become
misleading and must be revisited: the clients are not truly optional for production use.

Existing tests will fail and must be rewritten; `src/tests/gate.test.ts:34-41` currently
asserts the exact behavior this ADR removes.

Availability is now coupled to the policy engine and shield: if they are down, the gate
denies and simulations stop. This is the correct trade-off for a security boundary, but it
converts upstream outages into hard workflow failures and requires its own SLO.

Local development becomes marginally less convenient, requiring the explicit simulator
entrypoint rather than getting pass-through for free.

## Implementation Plan

1. Add `src/adapters/types.ts` declaring `PolicyEngineClient`, `ShieldClient`,
   `EdgeAgentClient`, `IncidentManagerClient`, and `ConfigManagerClient` with fully typed
   method signatures. No `Function` types.
2. Change each factory in `src/adapters/` to take its typed client as a **required**
   parameter and throw a named `AdapterNotConfiguredError` when it is absent, removing the
   `if (!client)` permissive branches at `policy.ts:7-10`, `shield.ts:7-10`,
   `edge-agent.ts:7-10`, `incident.ts:7-10`, and `config.ts:7-9, 14-16`.
3. Replace the assertions at `policy.ts:12` and `shield.ts:14` with runtime validators that
   reject malformed upstream responses; a rejected response raises, and the orchestrator
   converts it to a deny.
4. Add `src/adapters/simulator.ts` with explicitly named pass-through clients, and a
   `createSimulatorSecurityCore()` entrypoint that stamps `simulated: true` onto results and
   refuses to construct under `NODE_ENV === 'production'`.
5. Add `simulated?: boolean` to `GateResult` in `src/lib.ts` and propagate it through
   `src/services/orchestrator.ts`.
6. Wrap the policy call at `src/services/orchestrator.ts:65` in error handling that maps any
   thrown error to `decision: 'deny'` with a `policy-engine-unavailable` violation of
   severity `critical`.
7. Change `package.json:13` to `"test": "npm run build && node --test dist/tests/*.test.js"`
   and add `"pretest": "npm run build"` so a fresh clone cannot report a green no-op. If the
   toolchain supports it, prefer running TypeScript sources directly to remove the
   build-staleness failure mode entirely.
8. Rewrite `src/tests/gate.test.ts` so `createTestOrchestrator()` wires explicit typed test
   doubles, and invert the assertion at line 38 into the deny case described in Verification.
9. Update `README.md:58`, `README.md:167`, and `README.md:176` to describe simulator mode as
   an explicit non-production entrypoint, and correct the "All adapters support pass-through
   mode" claim.
10. Open a follow-up ADR for the `policyExempt` bypass at
    `src/services/orchestrator.ts:67-74`, covering who may set it and how it is authenticated.

## Verification

The change is complete when all of the following hold.

1. **Unconfigured gate denies.** This is the primary regression test for this ADR:

   ```ts
   const orchestrator = new SecurityOrchestrator({
     shield: createShieldAdapter(), edgeAgent: createEdgeAgentAdapter(),
     incident: createIncidentAdapter(), policy: createPolicyAdapter(),
     config: createConfigAdapter()
   });
   ```

   must **throw** at construction. If constructed by any other route with an
   unavailable policy client, `gate()` must return `decision: 'deny'` — never `'allow'` —
   with a violation whose `policy` is `policy-engine-unavailable` and severity `critical`.
   Over HTTP, the corresponding handler must return **403, not 200**.

2. **The current passing test now fails.** `src/tests/gate.test.ts:34-41` in its present
   form — no clients, asserting `decision === 'allow'` — must fail against the new
   implementation. If it still passes, the fix is not in effect.

3. **Upstream failure denies.** With a policy client whose `evaluate` rejects, and again
   with one that resolves to `undefined`, `null`, and `[{}]`, `gate()` returns `'deny'` in
   every case. No malformed response is coerced into an allow.

4. **Shield failure denies.** With a shield client whose `filter` rejects, `gate()` returns
   `'deny'` rather than proceeding with unfiltered content.

5. **No fabricated incident IDs.** Assert that no `GateResult.incidentId` produced outside
   explicit simulator mode matches `/^sim-incident-/`.

6. **Simulator mode is labelled and production-refused.** `createSimulatorSecurityCore()`
   yields results with `simulated: true`, and constructing it with
   `NODE_ENV=production` throws.

7. **Real deny still works.** The existing case at `src/tests/gate.test.ts:43-57` — a policy
   client returning `action: 'deny'` — continues to produce `decision: 'deny'`, a
   `block-policy` violation, and a real `incidentId`. Fail-closed must not mask genuine
   deny paths.

8. **`npm test` cannot report a false green.** On a clean checkout with no `dist/`,
   `npm test` either builds and runs the suite, or exits non-zero. A run reporting
   `tests 0` with exit code 0 is itself a failure of this criterion, and CI must assert a
   minimum test count.

9. **No `Function` types remain.** `grep -rn ": Function" src/` returns no matches, and
   `npm run lint` (`tsc --noEmit`, `package.json:14`) passes under `"strict": true`.

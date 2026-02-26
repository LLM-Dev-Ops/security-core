<div align="center">

<!-- Hero Banner -->
<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:161b22,100:1f6feb&height=220&section=header&text=LLM-Security-Core&fontSize=42&fontColor=ffffff&fontAlignY=35&desc=Enterprise%20Security%20Orchestration%20for%20LLM%20Applications&descSize=16&descAlignY=55&descColor=8b949e&animation=fadeIn" width="100%" alt="LLM-Security-Core Banner"/>

<br/>

<!-- Badges -->
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-3178c6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-ES2022-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)
[![License](https://img.shields.io/badge/License-LLMDevOps--PSACL_v1.0-red?style=for-the-badge)](#-license)
[![Cloud Run](https://img.shields.io/badge/Cloud_Run-Ready-4285F4?style=for-the-badge&logo=google-cloud&logoColor=white)](#-deployment)

<br/>

**Phase-8 / Layer-3 Core Integration Bundle**

A lightweight, stateless orchestration layer that coordinates security operations across
specialized LLM security services — without implementing core security logic itself.

[🚀 Quick Start](#-quick-start) •
[📖 Documentation](#-api-reference) •
[🏗️ Architecture](#-architecture) •
[🧪 Development](#-development)

<br/>

</div>

---

## ✨ Highlights

<table>
<tr>
<td width="50%">

🔗 **Unified Orchestration**<br/>
<sub>Single interface across 5 specialized security services</sub>

</td>
<td width="50%">

🛡️ **Security Gate**<br/>
<sub>Required entry point for enterprise simulation workflows</sub>

</td>
</tr>
<tr>
<td>

⚡ **Zero Infrastructure Overhead**<br/>
<sub>No retry logic, circuit breakers, caching, or metrics — pure delegation</sub>

</td>
<td>

🧪 **Simulator Mode**<br/>
<sub>Pass-through behavior when peer services aren't available</sub>

</td>
</tr>
<tr>
<td>

📡 **Execution Tracing**<br/>
<sub>Built-in span instrumentation for agentics-execution-engine</sub>

</td>
<td>

☁️ **Cloud Run Ready**<br/>
<sub>Stateless HTTP server deployable out of the box</sub>

</td>
</tr>
</table>

---

## 🚀 Quick Start

```bash
npm install llm-security-core
```

```typescript
import { createSecurityCore } from 'llm-security-core';

const security = createSecurityCore({
  shield: shieldInstance,
  edgeAgent: edgeAgentInstance,
  incidentManager: incidentManagerInstance,
  policyEngine: policyEngineInstance,
  configManager: configManagerInstance
});

const result = await security.process({
  id: 'req-123',
  type: 'prompt',
  content: 'User input to validate',
  metadata: { userId: 'user-456', sessionId: 'sess-789' }
});

if (result.allowed) {
  console.log('Content passed:', result.filtered);
} else {
  console.log('Blocked:', result.violations);
}
```

---

## 🏗️ Architecture

This package functions as a **pure orchestration layer** (Layer-3), delegating all security operations to specialized upstream services:

```
┌─────────────────────────────────────────────────────────────────┐
│                      LLM-Security-Core                          │
│                    (Orchestration Layer)                         │
├─────────────────────────────────────────────────────────────────┤
│  SecurityOrchestrator                                           │
│  ├── Policy Evaluation    ──▶  LLM-Policy-Engine     (L-14)    │
│  ├── Content Filtering    ──▶  LLM-Shield            (L-3)     │
│  ├── Runtime Enforcement  ──▶  LLM-Edge-Agent        (L-8)     │
│  ├── Incident Reporting   ──▶  LLM-Incident-Manager  (L-10)    │
│  └── Configuration        ──▶  LLM-Config-Manager    (L-18)    │
└─────────────────────────────────────────────────────────────────┘
```

<details>
<summary>🔄 <strong>Processing Flow</strong></summary>

<br/>

The `SecurityOrchestrator.process()` method executes a multi-stage pipeline:

| Step | Service | Action |
|:----:|---------|--------|
| 1️⃣ | **LLM-Policy-Engine** | Evaluate request against security policies |
| 2️⃣ | — | Deny check — if any policy returns `deny`, block immediately |
| 3️⃣ | **LLM-Shield** | Filter and redact content |
| 4️⃣ | **LLM-Edge-Agent** | Apply runtime enforcement controls |
| 5️⃣ | **LLM-Incident-Manager** | Report violations and anomalies |
| 6️⃣ | — | Assemble final result with filtered content + metadata |

```
Request ──▶ Policy ──▶ Filter ──▶ Enforce ──▶ Report ──▶ Result
              │          │          │           │
              ▼          ▼          ▼           ▼
           Deny?      Redact     Block?     Incident
```

</details>

<details>
<summary>🎯 <strong>Design Principles</strong></summary>

<br/>

| Principle | Description |
|-----------|-------------|
| 🪶 **Thin Adapters** | All integrations use minimal adapter interfaces that delegate to upstream systems |
| 🚫 **No Infrastructure Ownership** | Does not implement retry logic, circuit breakers, logging, metrics, tracing, rate limiting, or caching |
| 🧩 **No Core Logic** | Does not implement policy engines, filtering algorithms, or security detection logic |
| 🧪 **Simulator Compatible** | All adapters support pass-through mode for standalone testing |

</details>

<details>
<summary>📦 <strong>Peer Dependencies</strong></summary>

<br/>

All peer dependencies are optional — when absent, the orchestrator runs in simulator mode:

| Package | Purpose | Required |
|---------|---------|:--------:|
| `llm-shield` | Prompt and output content filtering | ❌ |
| `llm-edge-agent` | Runtime protection enforcement | ❌ |
| `llm-incident-manager` | Security alerting and escalation | ❌ |
| `llm-policy-engine` | Declarative security policy evaluation | ❌ |
| `llm-config-manager` | Centralized configuration management | ❌ |

</details>

---

## 📖 API Reference

<details>
<summary>🔌 <strong>Programmatic API</strong></summary>

<br/>

#### `createSecurityCore(options?)`

Factory function that creates a configured `SecurityOrchestrator` instance.

```typescript
import { createSecurityCore } from 'llm-security-core';

// Full configuration
const security = createSecurityCore({
  shield: shieldInstance,
  edgeAgent: edgeAgentInstance,
  incidentManager: incidentManagerInstance,
  policyEngine: policyEngineInstance,
  configManager: configManagerInstance
});

// Simulator mode (no dependencies)
const simulator = createSecurityCore();
```

#### `security.process(request)`

Process a security request through the full orchestration pipeline.

```typescript
const result = await security.process({
  id: 'req-123',
  type: 'prompt',        // 'prompt' | 'output' | 'runtime'
  content: 'Content to validate',
  context: {},           // optional
  metadata: {            // optional
    userId: 'user-456',
    sessionId: 'sess-789',
    timestamp: Date.now()
  }
});
```

</details>

<details>
<summary>🖥️ <strong>CLI</strong></summary>

<br/>

```bash
# Process content through security orchestration
llm-security check "Hello world" prompt

# Quick validation check
llm-security validate "User input here"

# Check service status
llm-security status
```

</details>

<details>
<summary>🌐 <strong>HTTP Server Endpoints</strong></summary>

<br/>

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/check` | Process a security request |
| `POST` | `/gate` | Execute security gate (required for simulations) |
| `POST` | `/v1/scan` | Non-blocking fan-out to Shield + Edge-Agent |
| `POST` | `/v1/audit/record` | Non-blocking fan-out to Incident-Manager + Policy-Engine |

```bash
# Start the server
npm start   # Listens on port 8080
```

</details>

<details>
<summary>📝 <strong>Type Definitions</strong></summary>

<br/>

```typescript
interface SecurityRequest {
  id: string;
  type: 'prompt' | 'output' | 'runtime';
  content: string;
  context?: Record<string, unknown>;
  metadata?: {
    userId?: string;
    sessionId?: string;
    timestamp?: number;
  };
}

interface SecurityResult {
  requestId: string;
  allowed: boolean;
  filtered?: string;
  redactions?: Array<{
    start: number;
    end: number;
    reason: string;
  }>;
  violations?: Array<{
    policy: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
  }>;
  incidentId?: string;
}

interface PolicyDecision {
  policyId: string;
  action: 'allow' | 'deny' | 'filter' | 'redact';
  reason?: string;
}

interface IncidentSignal {
  type: 'violation' | 'threshold' | 'anomaly';
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  details: Record<string, unknown>;
}
```

</details>

<details>
<summary>🔧 <strong>Adapter Interfaces</strong></summary>

<br/>

```typescript
interface ShieldAdapter {
  filter(content: string, mode: 'prompt' | 'output'): Promise<{
    filtered: string;
    redactions: SecurityResult['redactions'];
  }>;
}

interface EdgeAgentAdapter {
  enforce(request: SecurityRequest, decision: PolicyDecision): Promise<{
    enforced: boolean;
    modifications?: string;
  }>;
}

interface IncidentAdapter {
  emit(signal: IncidentSignal): Promise<{ incidentId: string }>;
}

interface PolicyAdapter {
  evaluate(request: SecurityRequest): Promise<PolicyDecision[]>;
}

interface ConfigAdapter {
  get<T>(key: string): Promise<T | undefined>;
  getSecret(key: string): Promise<string | undefined>;
}
```

</details>

<details>
<summary>📤 <strong>Exports</strong></summary>

<br/>

```typescript
// Core orchestrator
export { SecurityOrchestrator } from './services/orchestrator';

// Request handlers
export { handleSecurityRequest, handleSecurityEvent } from './handlers/security';

// Adapter factories
export { createShieldAdapter } from './adapters/shield';
export { createEdgeAgentAdapter } from './adapters/edge-agent';
export { createIncidentAdapter } from './adapters/incident';
export { createPolicyAdapter } from './adapters/policy';
export { createConfigAdapter } from './adapters/config';

// Convenience factory
export { createSecurityCore } from './sdk';
```

</details>

---

## 🧪 Development

```bash
# Build the project
npm run build

# Run tests
npm test

# Type-check without emitting
npm run lint

# Start the HTTP server
npm start
```

<details>
<summary>📂 <strong>Project Structure</strong></summary>

<br/>

```
src/
├── 📄 lib.ts                    # Types and re-exports
├── 📄 sdk.ts                    # SDK entry point
├── 📄 cli.ts                    # CLI interface
├── 📄 server.ts                 # HTTP server (Cloud Run)
├── 🔧 services/
│   ├── orchestrator.ts          # Core orchestration logic
│   └── router.ts                # Request routing
├── 📡 handlers/
│   └── security.ts              # Request/event handlers
├── 🔌 adapters/
│   ├── shield.ts                # LLM-Shield adapter
│   ├── edge-agent.ts            # LLM-Edge-Agent adapter
│   ├── incident.ts              # LLM-Incident-Manager adapter
│   ├── policy.ts                # LLM-Policy-Engine adapter
│   └── config.ts                # LLM-Config-Manager adapter
├── 📊 execution/
│   ├── types.ts                 # ExecutionSpan, ExecutionGraph types
│   └── span.ts                  # Span utilities
└── 🧪 tests/
    ├── orchestrator.test.ts     # Orchestrator tests
    ├── gate.test.ts             # Gate tests
    ├── execution.test.ts        # Execution span tests
    └── router.test.ts           # Router tests
```

</details>

---

## 📄 License

This project is licensed under the **LLMDevOps-PSACL v1.0** — a source-available commercial license owned by **Global Business Advisors Inc.**

A **commercial license is required** for production, enterprise, or customer-facing use.

📧 **Contact:** [sales@globalbusinessadvisors.co](mailto:sales@globalbusinessadvisors.co) | See [LICENSE.md](LICENSE.md) for full terms.

**© 2025 Global Business Advisors Inc. All rights reserved.**

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:161b22,100:1f6feb&height=100&section=footer" width="100%" alt="Footer"/>

<sub>Built with 🔒 for enterprise LLM security</sub>

</div>

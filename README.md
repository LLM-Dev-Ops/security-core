# LLM-Security-Core

**Phase-8 / Layer-3 Core Integration Bundle for Security Orchestration**

LLM-Security-Core is a coordination layer that orchestrates security operations across multiple LLM security services. It provides a unified interface for prompt/output filtering, policy enforcement, incident management, and runtime protection without implementing core security logic itself.

## Architecture

This package functions as a **pure orchestration layer** (Layer-3), delegating all security operations to specialized upstream services:

```
┌─────────────────────────────────────────────────────────────────┐
│                      LLM-Security-Core                          │
│                    (Orchestration Layer)                        │
├─────────────────────────────────────────────────────────────────┤
│  SecurityOrchestrator                                           │
│  ├── Policy Evaluation    ──▶  LLM-Policy-Engine (14)          │
│  ├── Content Filtering    ──▶  LLM-Shield (3)                  │
│  ├── Runtime Enforcement  ──▶  LLM-Edge-Agent (8)              │
│  ├── Incident Reporting   ──▶  LLM-Incident-Manager (10)       │
│  └── Configuration        ──▶  LLM-Config-Manager (18)         │
└─────────────────────────────────────────────────────────────────┘
```

### Design Principles

- **Thin Adapters**: All integrations use minimal adapter interfaces that delegate to upstream systems
- **No Infrastructure Ownership**: Does not implement retry logic, circuit breakers, logging, metrics, tracing, rate limiting, or caching
- **No Core Logic**: Does not implement policy engines, filtering algorithms, or security detection logic
- **Simulator Compatible**: All adapters support pass-through mode for standalone testing

## Installation

```bash
npm install llm-security-core
```

### Peer Dependencies

This package integrates with the following services (all optional):

| Package | Purpose |
|---------|---------|
| `llm-shield` | Prompt and output content filtering |
| `llm-edge-agent` | Runtime protection enforcement |
| `llm-incident-manager` | Security alerting and escalation |
| `llm-policy-engine` | Declarative security policy evaluation |
| `llm-config-manager` | Centralized configuration management |

## Usage

### Programmatic API

```typescript
import { createSecurityCore } from 'llm-security-core';

// Create orchestrator with integrated services
const security = createSecurityCore({
  shield: shieldInstance,
  edgeAgent: edgeAgentInstance,
  incidentManager: incidentManagerInstance,
  policyEngine: policyEngineInstance,
  configManager: configManagerInstance
});

// Process a security request
const result = await security.process({
  id: 'req-123',
  type: 'prompt',
  content: 'User input to validate',
  metadata: {
    userId: 'user-456',
    sessionId: 'sess-789'
  }
});

if (result.allowed) {
  console.log('Content passed:', result.filtered);
} else {
  console.log('Blocked:', result.violations);
}
```

### Simulator Mode

When peer dependencies are not provided, the orchestrator operates in simulator mode with pass-through behavior:

```typescript
import { createSecurityCore } from 'llm-security-core';

// No dependencies = simulator mode
const security = createSecurityCore();

const result = await security.process({
  id: 'test-1',
  type: 'prompt',
  content: 'Test content'
});
// result.allowed === true (pass-through)
```

### CLI

```bash
# Process content through security orchestration
llm-security check "Hello world" prompt

# Quick validation check
llm-security validate "User input here"

# Check service status
llm-security status
```

## API Reference

### Types

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

### Adapter Interfaces

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

### Exports

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

## Processing Flow

The `SecurityOrchestrator.process()` method executes the following flow:

1. **Policy Evaluation**: Requests are evaluated against policies via `LLM-Policy-Engine`
2. **Deny Check**: If any policy returns `deny`, the request is blocked immediately
3. **Content Filtering**: Content is filtered/redacted via `LLM-Shield`
4. **Runtime Enforcement**: Enforcement controls are applied via `LLM-Edge-Agent`
5. **Incident Reporting**: Violations are reported to `LLM-Incident-Manager`
6. **Result Assembly**: Final result is returned with filtered content and metadata

```
Request ──▶ Policy ──▶ Filter ──▶ Enforce ──▶ Report ──▶ Result
              │          │          │           │
              ▼          ▼          ▼           ▼
           Deny?      Redact     Block?     Incident
```

## Development

### Build

```bash
npm run build
```

### Test

```bash
npm test
```

### Lint

```bash
npm run lint
```

## Project Structure

```
src/
├── lib.ts                    # Types and re-exports
├── sdk.ts                    # SDK entry point
├── cli.ts                    # CLI interface
├── services/
│   └── orchestrator.ts       # Core orchestration logic
├── handlers/
│   └── security.ts           # Request/event handlers
├── adapters/
│   ├── shield.ts             # LLM-Shield adapter
│   ├── edge-agent.ts         # LLM-Edge-Agent adapter
│   ├── incident.ts           # LLM-Incident-Manager adapter
│   ├── policy.ts             # LLM-Policy-Engine adapter
│   └── config.ts             # LLM-Config-Manager adapter
└── tests/
    └── orchestrator.test.ts  # Test suite
```

## License

MIT

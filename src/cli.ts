#!/usr/bin/env node
// LLM-Security-Core CLI
import { SecurityOrchestrator } from './services/orchestrator.js';
import { createShieldAdapter } from './adapters/shield.js';
import { createEdgeAgentAdapter } from './adapters/edge-agent.js';
import { createIncidentAdapter } from './adapters/incident.js';
import { createPolicyAdapter } from './adapters/policy.js';
import { createConfigAdapter } from './adapters/config.js';
import type { SecurityRequest } from './lib.js';

const args = process.argv.slice(2);
const command = args[0];

function createSimulatorOrchestrator(): SecurityOrchestrator {
  return new SecurityOrchestrator({
    shield: createShieldAdapter(),
    edgeAgent: createEdgeAgentAdapter(),
    incident: createIncidentAdapter(),
    policy: createPolicyAdapter(),
    config: createConfigAdapter()
  });
}

async function main(): Promise<void> {
  switch (command) {
    case 'check': {
      const content = args[1] ?? '';
      const type = (args[2] as 'prompt' | 'output') ?? 'prompt';
      const orchestrator = createSimulatorOrchestrator();
      const request: SecurityRequest = { id: `cli-${Date.now()}`, type, content };
      const result = await orchestrator.process(request);
      console.log(JSON.stringify(result, null, 2));
      process.exit(result.allowed ? 0 : 1);
      break;
    }
    case 'validate': {
      const content = args[1] ?? '';
      const orchestrator = createSimulatorOrchestrator();
      const request: SecurityRequest = { id: `cli-${Date.now()}`, type: 'prompt', content };
      const result = await orchestrator.process(request);
      console.log(result.allowed ? 'VALID' : 'BLOCKED');
      if (result.violations) console.log('Violations:', result.violations.map(v => v.policy).join(', '));
      process.exit(result.allowed ? 0 : 1);
      break;
    }
    case 'status':
      console.log(JSON.stringify({ status: 'ready', mode: 'simulator', version: '1.0.0' }));
      break;
    case 'help':
    default:
      console.log(`LLM-Security-Core CLI

Commands:
  check <content> [type]  Process content through security orchestration
                          type: prompt | output (default: prompt)
  validate <content>      Quick validation check (returns VALID/BLOCKED)
  status                  Show service status
  help                    Show this help message

Examples:
  llm-security check "Hello world" prompt
  llm-security validate "User input here"
  llm-security status`);
  }
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});

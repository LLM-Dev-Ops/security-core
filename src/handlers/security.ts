// Security request and event handlers
import type { SecurityRequest, SecurityResult, IncidentSignal } from '../lib.js';
import { SecurityOrchestrator, OrchestratorConfig } from '../services/orchestrator.js';

let orchestrator: SecurityOrchestrator | null = null;

export function initializeOrchestrator(config: OrchestratorConfig): void {
  orchestrator = new SecurityOrchestrator(config);
}

export async function handleSecurityRequest(request: SecurityRequest): Promise<SecurityResult> {
  if (!orchestrator) {
    throw new Error('SecurityOrchestrator not initialized. Call initializeOrchestrator first.');
  }
  return orchestrator.process(request);
}

export async function handleSecurityEvent(event: { type: string; payload: unknown }): Promise<void> {
  if (!orchestrator) {
    throw new Error('SecurityOrchestrator not initialized. Call initializeOrchestrator first.');
  }

  // Route events to appropriate handling
  switch (event.type) {
    case 'security.request':
      await orchestrator.process(event.payload as SecurityRequest);
      break;
    case 'security.config.reload':
      // Config changes are handled by LLM-Config-Manager
      break;
    default:
      // Unknown events are logged but not processed
      break;
  }
}

export { initializeOrchestrator as init };

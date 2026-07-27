// Adapter for LLM-Incident-Manager (10) - Alerting and Escalation
import type { IncidentAdapter, IncidentSignal } from '../lib.js';
import {
  AdapterNotConfiguredError,
  validateIncidentResponse,
  type IncidentManagerClient
} from './types.js';

export function createIncidentAdapter(incidentManager?: IncidentManagerClient): IncidentAdapter {
  if (!incidentManager) {
    throw new AdapterNotConfiguredError('createIncidentAdapter', 'IncidentManagerClient');
  }
  return {
    async emit(signal: IncidentSignal) {
      return validateIncidentResponse(await incidentManager.emit(signal));
    }
  };
}

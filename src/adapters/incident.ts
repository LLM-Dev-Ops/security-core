// Adapter for LLM-Incident-Manager (10) - Alerting and Escalation
import type { IncidentAdapter, IncidentSignal } from '../lib.js';

export function createIncidentAdapter(incidentManager?: { emit: Function }): IncidentAdapter {
  return {
    async emit(signal: IncidentSignal) {
      if (!incidentManager) {
        // Simulator mode: generate mock incident ID
        return { incidentId: `sim-incident-${Date.now()}` };
      }
      const result = await incidentManager.emit(signal);
      return { incidentId: result.incidentId };
    }
  };
}

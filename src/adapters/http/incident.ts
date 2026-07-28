// HTTP IncidentManagerClient over llm-incident-manager.

import type { IncidentSignal } from '../../lib.js';
import type { IncidentManagerClient, IncidentEmitResponse } from '../types.js';
import { postJson, type HttpClientOptions } from './client.js';

export const DEFAULT_INCIDENT_EMIT_PATH = '/api/v1/events';

export function createHttpIncidentClient(
  options: HttpClientOptions,
  emitPath: string = DEFAULT_INCIDENT_EMIT_PATH
): IncidentManagerClient {
  return {
    async emit(signal: IncidentSignal): Promise<IncidentEmitResponse> {
      return await postJson('llm-incident-manager', options, emitPath, signal) as IncidentEmitResponse;
    }
  };
}

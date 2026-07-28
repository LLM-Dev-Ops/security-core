// HTTP EdgeAgentClient over llm-edge-agent.

import type {
  EdgeAgentClient,
  EdgeAgentEnforceRequest,
  EdgeAgentEnforceResponse
} from '../types.js';
import { postJson, type HttpClientOptions } from './client.js';

export const DEFAULT_EDGE_AGENT_ENFORCE_PATH = '/agents/tool-invocation/execute';

export function createHttpEdgeAgentClient(
  options: HttpClientOptions,
  enforcePath: string = DEFAULT_EDGE_AGENT_ENFORCE_PATH
): EdgeAgentClient {
  return {
    async enforce(input: EdgeAgentEnforceRequest): Promise<EdgeAgentEnforceResponse> {
      return await postJson('llm-edge-agent', options, enforcePath, input) as EdgeAgentEnforceResponse;
    }
  };
}

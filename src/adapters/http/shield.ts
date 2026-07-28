// HTTP ShieldClient over llm-shield.

import type {
  ShieldClient,
  ShieldFilterRequest,
  ShieldFilterResponse
} from '../types.js';
import { postJson, type HttpClientOptions } from './client.js';

export const DEFAULT_SHIELD_FILTER_PATH = '/api/v1/scan';

export function createHttpShieldClient(
  options: HttpClientOptions,
  filterPath: string = DEFAULT_SHIELD_FILTER_PATH
): ShieldClient {
  return {
    async filter(input: ShieldFilterRequest): Promise<ShieldFilterResponse> {
      return await postJson('llm-shield', options, filterPath, input) as ShieldFilterResponse;
    }
  };
}

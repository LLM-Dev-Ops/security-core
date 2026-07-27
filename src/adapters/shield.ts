// Adapter for LLM-Shield (3) - Prompt and Output Filtering
import type { ShieldAdapter } from '../lib.js';
import {
  AdapterNotConfiguredError,
  validateShieldResponse,
  type ShieldClient
} from './types.js';

export function createShieldAdapter(shield?: ShieldClient): ShieldAdapter {
  if (!shield) {
    throw new AdapterNotConfiguredError('createShieldAdapter', 'ShieldClient');
  }
  return {
    async filter(content: string, mode: 'prompt' | 'output') {
      return validateShieldResponse(await shield.filter({ content, mode }));
    }
  };
}

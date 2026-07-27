// Adapter for LLM-Config-Manager (18) - Centralized Configuration
import type { ConfigAdapter } from '../lib.js';
import {
  AdapterNotConfiguredError,
  validateSecret,
  type ConfigManagerClient
} from './types.js';

export function createConfigAdapter(configManager?: ConfigManagerClient): ConfigAdapter {
  if (!configManager) {
    throw new AdapterNotConfiguredError('createConfigAdapter', 'ConfigManagerClient');
  }
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const value = await configManager.get(key);
      return value === undefined || value === null ? undefined : (value as T);
    },
    async getSecret(key: string): Promise<string | undefined> {
      return validateSecret(await configManager.getSecret(key));
    }
  };
}

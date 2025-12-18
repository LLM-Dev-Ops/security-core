// Adapter for LLM-Config-Manager (18) - Centralized Configuration
import type { ConfigAdapter } from '../lib.js';

export function createConfigAdapter(configManager?: { get: Function; getSecret: Function }): ConfigAdapter {
  return {
    async get<T>(key: string): Promise<T | undefined> {
      if (!configManager) {
        // Simulator mode: return undefined (use defaults)
        return undefined;
      }
      return configManager.get(key);
    },
    async getSecret(key: string): Promise<string | undefined> {
      if (!configManager) {
        return undefined;
      }
      return configManager.getSecret(key);
    }
  };
}

// HTTP ConfigManagerClient over the configured config manager.
//
// This is the one upstream whose contract ADR-0002 could not settle: the
// service selected for CONFIG_MANAGER_URL self-identifies as something other
// than a config manager, and no existing code in this repository calls it. The
// binding is therefore deliberately generic — base URL and both paths are
// configuration, so correcting the target is an env var change rather than a
// code change. The raw body is returned so validateSecret() reports a shape
// mismatch loudly instead of it being absorbed here.

import type { ConfigManagerClient } from '../types.js';
import { getJson, type HttpClientOptions } from './client.js';

export const DEFAULT_CONFIG_GET_PATH = '/api/v1/config';
export const DEFAULT_CONFIG_SECRET_PATH = '/api/v1/secrets';

export interface ConfigManagerPaths {
  get?: string;
  secret?: string;
}

export function createHttpConfigManagerClient(
  options: HttpClientOptions,
  paths: ConfigManagerPaths = {}
): ConfigManagerClient {
  const getPath = paths.get ?? DEFAULT_CONFIG_GET_PATH;
  const secretPath = paths.secret ?? DEFAULT_CONFIG_SECRET_PATH;
  const at = (base: string, key: string) => `${base.replace(/\/$/, '')}/${encodeURIComponent(key)}`;

  return {
    async get(key: string): Promise<unknown> {
      return await getJson('llm-config-manager', options, at(getPath, key));
    },
    async getSecret(key: string): Promise<string | undefined> {
      return await getJson('llm-config-manager', options, at(secretPath, key)) as string | undefined;
    }
  };
}

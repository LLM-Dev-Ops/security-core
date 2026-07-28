// HTTP PolicyEngineClient over llm-policy-engine.
//
// Returns the raw decoded body. createPolicyAdapter() runs
// validatePolicyDecisions() over it, so a malformed upstream response must
// reach UpstreamResponseError rather than be papered over here.

import type { SecurityRequest, PolicyDecision } from '../../lib.js';
import type { PolicyEngineClient } from '../types.js';
import { postJson, type HttpClientOptions } from './client.js';

export const DEFAULT_POLICY_EVALUATE_PATH = '/api/evaluate';

export function createHttpPolicyEngineClient(
  options: HttpClientOptions,
  evaluatePath: string = DEFAULT_POLICY_EVALUATE_PATH
): PolicyEngineClient {
  return {
    async evaluate(request: SecurityRequest): Promise<PolicyDecision[]> {
      // `{context, action}` is the envelope router.ts already posts to this
      // same endpoint; SecurityRequest carries the action as `type`.
      const body = await postJson('llm-policy-engine', options, evaluatePath, {
        context: request,
        action: request.type
      });
      // Some deployments wrap the decision set in a `decisions` / `result` envelope.
      const record = body as Record<string, unknown> | null;
      const unwrapped = record?.decisions ?? record?.result ?? body;
      return unwrapped as PolicyDecision[];
    }
  };
}

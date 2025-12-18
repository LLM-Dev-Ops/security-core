// Adapter for LLM-Shield (3) - Prompt and Output Filtering
import type { ShieldAdapter, SecurityResult } from '../lib.js';

export function createShieldAdapter(shield?: { filter: Function }): ShieldAdapter {
  return {
    async filter(content: string, mode: 'prompt' | 'output') {
      if (!shield) {
        // Simulator mode: pass-through
        return { filtered: content, redactions: [] };
      }
      const result = await shield.filter({ content, mode });
      return {
        filtered: result.filtered ?? content,
        redactions: result.redactions as SecurityResult['redactions'] ?? []
      };
    }
  };
}

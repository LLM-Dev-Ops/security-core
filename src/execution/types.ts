// Execution span types for agentics-execution-engine integration
// Enforces hierarchical Core -> Repo -> Agent span invariant

import type { SecurityResult } from '../lib.js';

// ============================================================================
// Span primitives
// ============================================================================

export type SpanType = 'core' | 'repo' | 'agent';
export type SpanStatus = 'ok' | 'failed' | 'partial';

export interface ExecutionSpan {
  type: SpanType;
  span_id: string;
  parent_span_id: string | null;
  name: string;
  status: SpanStatus;
  start_time: string;
  end_time: string;
  attributes?: Record<string, unknown>;
  artifacts?: ExecutionArtifact[];
  evidence?: EvidenceReference[];
  children: ExecutionSpan[];
  failure_reasons?: string[];
}

// ============================================================================
// Artifacts & Evidence
// ============================================================================

export interface ExecutionArtifact {
  id: string;
  type: string;
  reference: string;
  metadata?: Record<string, unknown>;
}

export interface EvidenceReference {
  id: string;
  type: 'hash' | 'uri' | 'id';
  value: string;
  description?: string;
}

// ============================================================================
// Execution Graph
// ============================================================================

export interface ExecutionGraph {
  root: ExecutionSpan;
  span_count: number;
  depth: number;
  is_valid: boolean;
  validation_errors: string[];
}

// ============================================================================
// Core Execution Result (output contract)
// ============================================================================

export interface CoreExecutionResult {
  execution_graph: ExecutionGraph;
  result?: SecurityResult;
  status: SpanStatus;
  core_span_id: string;
}

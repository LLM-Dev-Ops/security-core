// Span factory and graph utilities for agentics-execution-engine
import { randomUUID, createHash } from 'node:crypto';
import type {
  ExecutionSpan,
  SpanType,
  SpanStatus,
  ExecutionArtifact,
  EvidenceReference,
  ExecutionGraph
} from './types.js';

// ============================================================================
// Span lifecycle
// ============================================================================

export function createSpan(opts: {
  type: SpanType;
  name: string;
  parent_span_id: string | null;
  attributes?: Record<string, unknown>;
}): ExecutionSpan {
  return {
    type: opts.type,
    span_id: randomUUID(),
    parent_span_id: opts.parent_span_id,
    name: opts.name,
    status: 'ok',
    start_time: new Date().toISOString(),
    end_time: '',
    attributes: opts.attributes,
    children: []
  };
}

export function finalizeSpan(span: ExecutionSpan, status?: SpanStatus): void {
  span.end_time = new Date().toISOString();
  if (status !== undefined) {
    span.status = status;
  }
}

export function failSpan(span: ExecutionSpan, ...reasons: string[]): void {
  span.status = 'failed';
  span.end_time = new Date().toISOString();
  if (!span.failure_reasons) span.failure_reasons = [];
  span.failure_reasons.push(...reasons);
}

// ============================================================================
// Artifacts & Evidence
// ============================================================================

export function attachArtifact(span: ExecutionSpan, artifact: ExecutionArtifact): void {
  if (!span.artifacts) span.artifacts = [];
  span.artifacts.push(artifact);
}

export function attachEvidence(span: ExecutionSpan, evidence: EvidenceReference): void {
  if (!span.evidence) span.evidence = [];
  span.evidence.push(evidence);
}

export function hashEvidence(data: unknown): string {
  return createHash('sha256')
    .update(JSON.stringify(data))
    .digest('hex');
}

// ============================================================================
// Execution Graph construction & validation
// ============================================================================

function countSpans(span: ExecutionSpan): number {
  let count = 1;
  for (const child of span.children) {
    count += countSpans(child);
  }
  return count;
}

function measureDepth(span: ExecutionSpan): number {
  if (span.children.length === 0) return 1;
  let maxChildDepth = 0;
  for (const child of span.children) {
    const d = measureDepth(child);
    if (d > maxChildDepth) maxChildDepth = d;
  }
  return 1 + maxChildDepth;
}

export function validateExecutionGraph(root: ExecutionSpan): string[] {
  const errors: string[] = [];

  // Core span must exist with correct type
  if (root.type !== 'core') {
    errors.push(`Root span type is "${root.type}", expected "core"`);
  }

  // Must have repo-level child spans
  const repoSpans = root.children.filter(c => c.type === 'repo');
  if (repoSpans.length === 0) {
    errors.push('No repo-level child spans exist');
  }

  // Each repo must have at least one agent-level child span
  for (const repo of repoSpans) {
    if (repo.children.length === 0) {
      errors.push(`Repo "${repo.name}" returned zero spans`);
      continue;
    }
    const agentSpans = repo.children.filter(c => c.type === 'agent');
    if (agentSpans.length === 0) {
      errors.push(`Repo "${repo.name}" lacks agent-level child spans`);
    }
  }

  // Verify parent_span_id consistency
  for (const repo of repoSpans) {
    if (repo.parent_span_id !== root.span_id) {
      errors.push(`Repo "${repo.name}" parent_span_id mismatch`);
    }
    for (const agent of repo.children) {
      if (agent.parent_span_id !== repo.span_id) {
        errors.push(`Agent "${agent.name}" in repo "${repo.name}" parent_span_id mismatch`);
      }
    }
  }

  return errors;
}

export function buildExecutionGraph(root: ExecutionSpan): ExecutionGraph {
  const validationErrors = validateExecutionGraph(root);
  const isValid = validationErrors.length === 0;

  // If invalid, mark core span as failed per enforcement rules
  if (!isValid && root.status === 'ok') {
    root.status = 'failed';
    if (!root.failure_reasons) root.failure_reasons = [];
    root.failure_reasons.push(...validationErrors);
  }

  return {
    root,
    span_count: countSpans(root),
    depth: measureDepth(root),
    is_valid: isValid,
    validation_errors: validationErrors
  };
}

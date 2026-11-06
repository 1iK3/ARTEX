import type { AuditEngineJob, AuditProgress } from "./types.ts";

export interface EngineVisibilityRow {
  engine: string;
  intentId?: number;
  jobKind?: string;
  status?: string;
  queryHash?: string;
  resultCount?: number;
  duration: string;
  error?: string;
}

export function formatDuration(ms?: number): string {
  if (!ms || ms <= 0) return "—";
  if (ms < 1_000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1_000).toFixed(2).replace(/\.?0+$/, "")}s`;
  const totalSeconds = Math.round(ms / 1_000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return seconds === 0 ? `${minutes}m` : `${minutes}m ${seconds}s`;
}

export function engineVisibilityRows(progress: AuditProgress | null): EngineVisibilityRow[] {
  if (!progress || !Array.isArray(progress.engines)) return [];
  const latest = new Map<string, AuditEngineJob>();
  for (const job of progress.engines) {
    const engine = job.engine?.trim();
    if (!engine) continue;
    latest.set(engine, job);
  }
  return [...latest.entries()].map(([engine, job]) => ({
    engine,
    intentId: job.intent_id,
    jobKind: job.job_kind,
    status: job.status,
    queryHash: job.query_hash,
    resultCount: job.result_count,
    duration: formatDuration(job.duration_ms),
    error: job.error?.trim() ?? "",
  }));
}

export function engineVisibilityIssues(progress: AuditProgress | null): string[] {
  const status = progress?.engine_status;
  if (!status) return [];
  const values = [
    ...(status.warnings ?? []),
    ...(status.gaps ?? []),
    ...(status.intent_analysis?.query_gaps ?? []),
  ];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    const text = value?.trim();
    if (!text || seen.has(text)) continue;
    seen.add(text);
    out.push(text);
  }
  return out;
}
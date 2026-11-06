import type { AuditCoverageGapRow, AuditProgress } from "./types.ts";

const GAP_STATUSES = new Set(["planned", "missed", "exempt"]);

export function coverageGapRows(progress: AuditProgress | null, limit = 20): AuditCoverageGapRow[] {
  if (!progress?.coverage_detail?.rows) return [];
  return progress.coverage_detail.rows
    .filter((row) => GAP_STATUSES.has((row.status ?? "").toLowerCase()))
    .slice(0, Math.max(0, limit));
}

export function coverageGapSummary(
  progress: AuditProgress | null,
  limit = 20,
): { total: number; shown: number; uncoveredCWEs: string[] } {
  const rows = coverageGapRows(progress, Number.MAX_SAFE_INTEGER);
  return {
    total: rows.length,
    shown: Math.min(rows.length, Math.max(0, limit)),
    uncoveredCWEs: progress?.coverage_detail?.uncovered_cwes ?? [],
  };
}
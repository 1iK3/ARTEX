import type { CodeLocation } from "./types";

export interface AuditSourceTarget {
  path: string;
  line?: number;
  endLine?: number;
}

export interface AuditSourceWindow {
  start_line: number;
  end_line: number;
}

export interface AuditHighlightRange {
  start: number;
  end: number;
}

function positiveLine(value?: number): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) return undefined;
  return Math.floor(value);
}

export function auditSourceTarget(location?: CodeLocation | null): AuditSourceTarget | null {
  if (!location?.path) return null;
  const line = positiveLine(location.line);
  const endLine = positiveLine(location.end_line);
  const validEndLine = line && endLine && endLine >= line ? endLine : undefined;
  return { path: location.path, line, endLine: validEndLine };
}

export function auditHighlightRange(
  target: AuditSourceTarget | null,
  window: AuditSourceWindow,
): AuditHighlightRange | null {
  const start = positiveLine(target?.line);
  if (!start || start < window.start_line || start > window.end_line) return null;
  const requestedEnd = positiveLine(target?.endLine) ?? start;
  const end = Math.min(Math.max(requestedEnd, start), window.end_line);
  return { start, end };
}

export function isAuditHighlightedLine(line: number, range: AuditHighlightRange | null): boolean {
  return range !== null && line >= range.start && line <= range.end;
}

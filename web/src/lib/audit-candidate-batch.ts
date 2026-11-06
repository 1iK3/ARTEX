import type { AuditCandidate } from "./types";

export function auditFindingVerificationBatchPath(taskId: string): string {
  return `/tasks/${encodeURIComponent(taskId)}/audit/findings/verification-batch`;
}

export function auditCandidateRowKey(candidate: AuditCandidate, index: number): string {
  if (candidate.id !== undefined && candidate.id !== null && candidate.id !== "") {
    return `candidate:${String(candidate.id)}`;
  }
  return `candidate:${candidate.phase ?? "candidate"}-${candidate.cwe ?? ""}-${index}`;
}

export function isAuditCandidateSelectable(candidate: AuditCandidate): boolean {
  return Boolean(candidate.finding_ids?.some((id) => Number.isInteger(id) && id > 0));
}

export function selectedAuditFindingIds(
  candidates: AuditCandidate[] | undefined,
  selectedKeys: ReadonlySet<string>,
): number[] {
  if (!Array.isArray(candidates)) return [];

  const findingIds: number[] = [];
  const seen = new Set<number>();
  candidates.forEach((candidate, index) => {
    if (!selectedKeys.has(auditCandidateRowKey(candidate, index))) return;
    for (const findingID of candidate.finding_ids ?? []) {
      if (!Number.isInteger(findingID) || findingID <= 0 || seen.has(findingID)) continue;
      seen.add(findingID);
      findingIds.push(findingID);
    }
  });
  return findingIds;
}

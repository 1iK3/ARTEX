import {
  auditCandidateRowKey,
  auditFindingVerificationBatchPath,
  isAuditCandidateSelectable,
  selectedAuditFindingIds,
} from "./audit-candidate-batch.ts";
import type { AuditCandidate } from "./types";
import assert from "node:assert/strict";
import test from "node:test";

const candidates: AuditCandidate[] = [
  { id: "first", phase: "S5", cwe: "CWE-89", finding_ids: [18, 19] },
  { phase: "S8", cwe: "CWE-79", finding_ids: [20] },
  { id: "second", phase: "S10", finding_ids: [19, 21] },
  { id: "no-findings", phase: "S6" },
  { id: "invalid-only", finding_ids: [0, -1] },
];

test("auditCandidateRowKey uses id before a stable fallback", () => {
  assert.equal(auditCandidateRowKey({ id: "first" }, 0), "candidate:first");
  assert.equal(auditCandidateRowKey({ phase: "S8", cwe: "CWE-79" }, 1), "candidate:S8-CWE-79-1");
});

test("isAuditCandidateSelectable requires at least one valid finding id", () => {
  assert.equal(isAuditCandidateSelectable(candidates[0]), true);
  assert.equal(isAuditCandidateSelectable(candidates[3]), false);
  assert.equal(isAuditCandidateSelectable(candidates[4]), false);
});

test("selectedAuditFindingIds flattens, dedupes, and preserves order", () => {
  const selectedKeys = new Set([
    auditCandidateRowKey(candidates[0], 0),
    auditCandidateRowKey(candidates[1], 1),
    auditCandidateRowKey(candidates[2], 2),
  ]);

  assert.deepEqual(selectedAuditFindingIds(candidates, selectedKeys), [18, 19, 20, 21]);
});

test("selectedAuditFindingIds tolerates partial projections", () => {
  assert.deepEqual(selectedAuditFindingIds([], new Set()), []);
  assert.deepEqual(selectedAuditFindingIds(candidates, new Set()), []);
  assert.deepEqual(selectedAuditFindingIds(undefined, new Set(["candidate:first"])), []);
});

test("auditFindingVerificationBatchPath encodes the task id", () => {
  assert.equal(auditFindingVerificationBatchPath("task/1"), "/tasks/task%2F1/audit/findings/verification-batch");
});

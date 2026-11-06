import assert from "node:assert/strict";
import test from "node:test";

import {
  engineVisibilityIssues,
  engineVisibilityRows,
  formatDuration,
} from "./audit-engine-visibility.ts";
import type { AuditProgress } from "./types";

test("formatDuration renders bounded human-readable durations", () => {
  assert.equal(formatDuration(), "—");
  assert.equal(formatDuration(0), "—");
  assert.equal(formatDuration(999), "999ms");
  assert.equal(formatDuration(1_250), "1.25s");
  assert.equal(formatDuration(61_000), "1m 1s");
  assert.equal(formatDuration(3_600_000), "60m");
});

test("engineVisibilityRows shows the latest safe job fields per engine", () => {
  const progress = {
    engines: [
      { engine: "codeql", job_kind: "prepare", status: "done", query_hash: "old", result_count: 0 },
      { engine: "codeql", intent_id: 11, job_kind: "run", status: "done", query_hash: "query-hash", result_count: 3, duration_ms: 1250, error: "safe error" },
      { engine: "joern", job_kind: "run", status: "failed", query_hash: "joern-hash", result_count: 0, duration_ms: 4000 },
    ],
  } as AuditProgress;

  assert.deepEqual(engineVisibilityRows(progress), [
    { engine: "codeql", intentId: 11, jobKind: "run", status: "done", queryHash: "query-hash", resultCount: 3, duration: "1.25s", error: "safe error" },
    { engine: "joern", intentId: undefined, jobKind: "run", status: "failed", queryHash: "joern-hash", resultCount: 0, duration: "4s", error: "" },
  ]);
});

test("engineVisibilityRows rejects legacy non-array engine state", () => {
  const progress = { engines: { codeql: "auto" } } as AuditProgress;
  assert.deepEqual(engineVisibilityRows(progress), []);
});

test("engineVisibilityIssues deduplicates warnings, gaps, and query gaps", () => {
  const progress = {
    engine_status: {
      warnings: ["same warning", "engine warning"],
      gaps: ["same warning", "engine gap"],
      intent_analysis: { query_gaps: ["query gap"] },
    },
  } as AuditProgress;

  assert.deepEqual(engineVisibilityIssues(progress), [
    "same warning",
    "engine warning",
    "engine gap",
    "query gap",
  ]);
});
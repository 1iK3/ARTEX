import assert from "node:assert/strict";
import test from "node:test";

import { coverageGapRows, coverageGapSummary } from "./audit-coverage-visibility.ts";
import type { AuditProgress } from "./types.ts";

const progress = {
  coverage_detail: {
    rows: [
      { status: "missed", kind: "cwe", cwe: "CWE-79", reason: "not reached" },
      { status: "planned", kind: "sink_site", cwe: "CWE-79", path: "internal/pay/db.go", line: 42, sink_key: "sink:db" },
      { status: "scanned", kind: "sink_site", cwe: "CWE-89", path: "internal/pay/safe.go", line: 1 },
      { status: "exempt", kind: "sink_site", cwe: "CWE-434", path: "internal/upload.go", line: 8, reason: "no_sinks" },
    ],
    uncovered_cwes: ["CWE-79", "CWE-434"],
  },
} as AuditProgress;

test("coverageGapRows filters statuses and applies the requested limit", () => {
  const rows = coverageGapRows(progress, 2);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].status, "missed");
  assert.equal(rows[1].status, "planned");
});

test("coverageGapSummary reports totals and uncovered CWEs", () => {
  assert.deepEqual(coverageGapSummary(progress, 2), {
    total: 3,
    shown: 2,
    uncoveredCWEs: ["CWE-79", "CWE-434"],
  });
});

test("coverage visibility helpers tolerate missing detail", () => {
  assert.deepEqual(coverageGapRows({}, 2), []);
  assert.deepEqual(coverageGapSummary({}, 2), { total: 0, shown: 0, uncoveredCWEs: [] });
});
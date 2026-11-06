import { auditHighlightRange, auditSourceTarget, isAuditHighlightedLine } from "./audit-source-highlight.ts";
import assert from "node:assert/strict";
import test from "node:test";

test("audit source target preserves a valid line range", () => {
  assert.deepEqual(auditSourceTarget({ path: "src/app.go", line: 42, end_line: 47 }), {
    path: "src/app.go",
    line: 42,
    endLine: 47,
  });
});

test("audit source target ignores an invalid end line", () => {
  assert.deepEqual(auditSourceTarget({ path: "src/app.go", line: 42, end_line: 40 }), {
    path: "src/app.go",
    line: 42,
    endLine: undefined,
  });
});

test("audit highlight range clamps to the returned source window", () => {
  const target = auditSourceTarget({ path: "src/app.go", line: 30, end_line: 250 });
  const range = auditHighlightRange(target, { start_line: 30, end_line: 229 });

  assert.deepEqual(range, { start: 30, end: 229 });
  assert.equal(isAuditHighlightedLine(30, range), true);
  assert.equal(isAuditHighlightedLine(229, range), true);
  assert.equal(isAuditHighlightedLine(230, range), false);
});

test("audit highlight range is empty for a target outside the file", () => {
  const target = auditSourceTarget({ path: "src/app.go", line: 300 });

  assert.deepEqual(auditHighlightRange(target, { start_line: 1, end_line: 200 }), null);
  assert.equal(isAuditHighlightedLine(300, null), false);
});

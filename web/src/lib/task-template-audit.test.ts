import {
  buildTaskTemplateAuditInput,
  defaultTaskTemplateAuditConfigText,
  parseTaskTemplateAuditConfig,
  taskTemplateAuditDraft,
} from "./task-template-audit.ts";
import type { TaskTemplate } from "./types.ts";
import assert from "node:assert/strict";
import test from "node:test";

const codeAuditTemplate = {
  task_mode: "code_audit",
  audit_config: { source_type: "zip", upload_id: "u", depth: "deep" },
} as TaskTemplate;

test("task template audit draft formats a code audit template", () => {
  const draft = taskTemplateAuditDraft(codeAuditTemplate);

  assert.equal(draft.taskMode, "code_audit");
  assert.equal(draft.auditConfigText, JSON.stringify(codeAuditTemplate.audit_config, null, 2));
});

test("task template audit draft leaves pentest templates empty", () => {
  const draft = taskTemplateAuditDraft({ task_mode: "pentest" } as TaskTemplate);

  assert.deepEqual(draft, { taskMode: "pentest", auditConfigText: "" });
});

test("task template audit config parsing rejects blank and non-object JSON", async () => {
  await assert.rejects(parseTaskTemplateAuditConfig(" "), /audit_config 不能为空/);
  await assert.rejects(parseTaskTemplateAuditConfig("[]"), /必须是 JSON 对象/);
});

test("task template audit input includes config only for code audit", async () => {
  const config = { source_type: "zip", upload_id: "u", depth: "deep" };
  const text = JSON.stringify(config);

  assert.deepEqual(await buildTaskTemplateAuditInput("pentest", ""), { task_mode: "pentest" });
  assert.deepEqual(await buildTaskTemplateAuditInput("code_audit", text), {
    task_mode: "code_audit",
    audit_config: config,
  });
});

test("default task template audit config is valid JSON", async () => {
  const config = await parseTaskTemplateAuditConfig(defaultTaskTemplateAuditConfigText());

  assert.equal(config.source_type, "zip");
  assert.equal(config.depth, "deep");
  assert.equal(config.cwe_scope, "core");
});

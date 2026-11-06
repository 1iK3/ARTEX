import type { AuditConfig, TaskMode, TaskTemplate } from "./types";

export interface TaskTemplateAuditDraft {
  taskMode: TaskMode;
  auditConfigText: string;
}

export function taskTemplateAuditDraft(
  template?: Pick<TaskTemplate, "task_mode" | "audit_config"> | null,
): TaskTemplateAuditDraft {
  const taskMode = template?.task_mode === "code_audit" ? "code_audit" : "pentest";
  const auditConfigText =
    taskMode === "code_audit" && template?.audit_config ? JSON.stringify(template.audit_config, null, 2) : "";
  return { taskMode, auditConfigText };
}

export function defaultTaskTemplateAuditConfigText(): string {
  return JSON.stringify(
    {
      source_type: "zip",
      upload_id: "template-upload-id",
      depth: "deep",
      cwe_scope: "core",
      languages: [],
      max_rounds: 5,
      engines: { codegraph: "required", codeql: "auto", joern: "auto" },
      include_tests: false,
      include_vendor: false,
    },
    null,
    2,
  );
}

export async function parseTaskTemplateAuditConfig(text: string): Promise<AuditConfig> {
  const trimmed = text.trim();
  if (!trimmed) throw new Error("代码审计模板的 audit_config 不能为空");
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error("audit_config 必须是合法 JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("audit_config 必须是 JSON 对象");
  }
  return parsed as AuditConfig;
}

export async function buildTaskTemplateAuditInput(
  taskMode: TaskMode,
  auditConfigText: string,
): Promise<{ task_mode: TaskMode; audit_config?: AuditConfig }> {
  if (taskMode === "pentest") return { task_mode: taskMode };
  return {
    task_mode: taskMode,
    audit_config: await parseTaskTemplateAuditConfig(auditConfigText),
  };
}

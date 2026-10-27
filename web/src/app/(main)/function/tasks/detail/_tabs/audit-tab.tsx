"use client";

import * as React from "react";

import {
  AlertTriangleIcon,
  CheckIcon,
  CpuIcon,
  DownloadIcon,
  FileTextIcon,
  GaugeIcon,
  ListChecksIcon,
  RefreshCwIcon,
  ShieldCheckIcon,
  XIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type {
  AuditCandidate,
  AuditCapabilities,
  AuditCoverage,
  AuditEngineJob,
  AuditEngineState,
  AuditGate,
  AuditHypothesis,
  AuditPhase,
  AuditProgress,
  AuditRound,
} from "@/lib/types";
import { cn } from "@/lib/utils";

const POLL_MS = 5000;

const PHASE_LABELS: Record<string, string> = {
  S0: "源码摄取",
  S1: "仓库画像",
  S2: "攻击面梳理",
  S3: "数据流分析",
  S4: "漏洞检测",
  S5: "候选验证",
  S6: "逻辑漏洞",
  S7: "深度审计",
  S8: "设计校验",
  S9: "深度补扫",
  S10: "PoC 分析",
  S11: "报告生成",
};

const STATUS_LABELS: Record<string, string> = {
  ingest: "摄取中",
  running: "运行中",
  round_review: "轮次复核",
  completed: "已收敛",
  done: "已完成",
  done_with_gaps: "完成（有缺口）",
  failed: "失败",
  pending: "待执行",
  active: "执行中",
  skipped: "已跳过",
  exempt: "已豁免",
  ready: "就绪",
  unavailable: "不可用",
  pass: "通过",
  passed: "通过",
  retry: "需重试",
  blocked: "阻塞",
  exhausted: "已耗尽",
  confirmed: "已确认",
  refuted: "已反驳",
  design_intent: "设计意图",
  candidate: "候选",
  unverified: "未验证",
};

const SEVERITY_LABELS: Record<string, string> = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
};

const DECISION_LABELS: Record<string, string> = {
  continue: "继续下一轮",
  complete: "完成",
  completed: "完成",
  complete_with_gaps: "完成（有缺口）",
  complete_forced: "强制完成",
  stop: "停止",
  failed: "失败",
};

const GATE_LABELS: Record<string, string> = {
  "gate-phase": "Gate-Phase / 阶段",
  phase: "Gate-Phase / 阶段",
  "gate-coverage": "Gate-Coverage / 覆盖",
  coverage: "Gate-Coverage / 覆盖",
  "gate-cwe": "Gate-CWE / CWE",
  cwe: "Gate-CWE / CWE",
  "gate-c": "Gate-C / 收敛",
  c: "Gate-C / 收敛",
  "gate-h": "Gate-H / 假设",
  h: "Gate-H / 假设",
  "gate-e": "Gate-E / 证据",
  e: "Gate-E / 证据",
  engine: "Gate-Engine / 引擎",
  "gate-engine": "Gate-Engine / 引擎",
};

function label(value: string | undefined, fallback = "—"): string {
  if (!value) return fallback;
  return STATUS_LABELS[value.toLowerCase()] ?? value;
}

function phaseLabel(phase: string | undefined): string {
  if (!phase) return "—";
  return PHASE_LABELS[phase] ? `${phase} ${PHASE_LABELS[phase]}` : phase;
}

function fmtTime(value?: string): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString("zh-CN", { hour12: false });
}

function pct(value?: number): string {
  if (typeof value !== "number" || Number.isNaN(value)) return "—";
  return `${Math.round(value * 100)}%`;
}

function pctValue(value?: number): number {
  if (typeof value !== "number" || Number.isNaN(value)) return 0;
  return Math.max(0, Math.min(100, Math.round(value * 100)));
}

function phaseReason(phase: AuditPhase): string {
  if (phase.reason) return phase.reason;
  const gate = phase.gate;
  if (typeof gate === "string") return gate;
  if (gate && typeof gate === "object" && typeof gate.reason === "string") return gate.reason;
  return "—";
}

function statusTone(status?: string): string {
  switch (status?.toLowerCase()) {
    case "done":
    case "completed":
    case "pass":
    case "passed":
    case "ready":
    case "confirmed":
      return "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
    case "running":
    case "active":
    case "ingest":
    case "round_review":
      return "border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-300";
    case "failed":
    case "blocked":
    case "refuted":
      return "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300";
    case "skipped":
    case "exempt":
    case "pending":
    case "candidate":
    case "unverified":
      return "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300";
    default:
      return "border-border bg-muted/40 text-muted-foreground";
  }
}

function StatusPill({ value }: { value?: string }) {
  if (!value) return <span className="text-muted-foreground">—</span>;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        statusTone(value),
      )}
    >
      {label(value)}
    </span>
  );
}

function SummaryItem({
  label: itemLabel,
  value,
  sub,
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
}) {
  return (
    <div className="min-w-0 rounded-lg border bg-card px-3 py-2.5">
      <div className="text-[11px] font-medium text-muted-foreground">{itemLabel}</div>
      <div className="mt-0.5 truncate text-sm font-semibold" title={typeof value === "string" ? value : undefined}>
        {value || "—"}
      </div>
      {sub && <div className="mt-0.5 truncate text-[11px] text-muted-foreground">{sub}</div>}
    </div>
  );
}

interface GateRow {
  key: string;
  gate: AuditGate;
}

function normalizeGates(gates: AuditProgress["gates"]): GateRow[] {
  if (!gates) return [];
  if (Array.isArray(gates)) {
    return gates.map((gate, index) => ({
      key: gate.name ?? `gate-${index}`,
      gate,
    }));
  }
  return Object.entries(gates).map(([key, value]) => {
    if (typeof value === "string") {
      const lowered = value.toLowerCase();
      return {
        key,
        gate: {
          name: GATE_LABELS[key.toLowerCase()] ?? key,
          passed: ["pass", "passed", "ok", "ready", "true"].includes(lowered),
          reason: value,
        },
      };
    }
    return { key, gate: value };
  });
}

function gateLabel(key: string, gate: AuditGate): string {
  const normalized = key.toLowerCase();
  return GATE_LABELS[normalized] ?? gate.name ?? key;
}

// 顶层 gates 只保证 phase/coverage/cwe；C/H/E/Engine 门禁来自轮次记录。
// 把最近一轮里尚未出现在顶层 gates 的项补到卡片中，避免 UI 漏掉轮次门禁。
function supplementRoundGates(rows: GateRow[], rounds: AuditRound[]): GateRow[] {
  const latest = rounds[rounds.length - 1];
  if (!latest) return rows;
  const existing = new Set<string>();
  for (const { key, gate } of rows) {
    existing.add(key.toLowerCase().replace(/^gate-/, ""));
    if (gate.name) {
      existing.add(
        gate.name
          .toLowerCase()
          .replace(/^gate-/, "")
          .split(" / ")[0],
      );
    }
  }
  const mapping: { key: string; name: string; value?: string }[] = [
    { key: "c", name: "Gate-C / 收敛", value: latest.gate_c },
    { key: "cwe", name: "Gate-CWE / CWE", value: latest.gate_cwe },
    { key: "h", name: "Gate-H / 假设", value: latest.gate_h },
    { key: "e", name: "Gate-E / 证据", value: latest.gate_e },
    { key: "coverage", name: "Gate-Coverage / 覆盖", value: latest.gate_coverage },
    { key: "engine", name: "Gate-Engine / 引擎", value: latest.gate_engine },
  ];
  const extra = mapping
    .filter((item) => item.value && !existing.has(item.key))
    .map((item) => ({
      key: item.key,
      gate: {
        name: item.name,
        passed: ["pass", "passed", "true", "ok"].includes(item.value?.toLowerCase() ?? ""),
        reason: `轮次 R${latest.round}：${label(item.value)}`,
      },
    }));
  return [...rows, ...extra];
}

interface EngineJobSummary {
  total: number;
  running: number;
  failed: number;
  results: number;
  lastStatus?: string;
  state?: string;
  reason?: string;
}

function allEngineJobs(progress: AuditProgress | null): AuditEngineJob[] {
  return Array.isArray(progress?.engines) ? progress.engines : [];
}

function summarizeEngine(progress: AuditProgress | null, name: string): EngineJobSummary {
  const jobs = allEngineJobs(progress).filter((job) => job.engine?.toLowerCase() === name);
  const summary: EngineJobSummary = {
    total: jobs.length,
    running: jobs.filter((job) => ["running", "preparing", "queued"].includes(job.status ?? "")).length,
    failed: jobs.filter((job) => ["failed", "error", "timeout"].includes(job.status ?? "")).length,
    results: jobs.reduce((sum, job) => sum + (job.result_count ?? 0), 0),
  };
  if (jobs.length > 0) summary.lastStatus = jobs[jobs.length - 1]?.status;
  if (progress?.engines && !Array.isArray(progress.engines)) {
    const state = progress.engines[name];
    if (typeof state === "string") {
      summary.state = state;
    } else if (state && typeof state === "object") {
      const engineState = state as AuditEngineState;
      summary.state = engineState.state;
      summary.reason = engineState.reason;
    }
  }
  return summary;
}

function engineConfig(progress: AuditProgress | null, name: string): string {
  const engines = progress?.budget?.engines;
  if (engines && typeof engines === "object") {
    const value = engines[name];
    if (typeof value === "string") return value;
  }
  return "—";
}

function EngineCard({
  name,
  capability,
  jobSummary,
  configured,
  loading,
}: {
  name: string;
  capability?: { available?: boolean; version?: string; path?: string };
  jobSummary: EngineJobSummary;
  configured: string;
  loading: boolean;
}) {
  const available = Boolean(capability?.available);
  const state = jobSummary.state;
  let stateLabel = loading ? "探测中" : available ? "可用" : "未检测到";
  if (state) stateLabel = label(state);
  let subtitle = loading ? "正在探测可执行文件…" : "PATH 中未找到";
  if (capability?.version?.trim()) subtitle = capability.version;
  else if (capability?.path?.trim()) subtitle = capability.path;
  const hasJobs = jobSummary.total > 0;
  return (
    <Card size="sm" className="gap-2">
      <CardHeader className="gap-0.5">
        <CardTitle className="flex items-center justify-between gap-2 text-sm">
          <span className="flex items-center gap-1.5">
            <CpuIcon className="size-3.5" /> {name}
          </span>
          <span
            className={cn(
              "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-medium",
              available ? statusTone("ready") : statusTone("unavailable"),
            )}
          >
            <span className={cn("size-1.5 rounded-full", available ? "bg-emerald-500" : "bg-muted-foreground/50")} />
            {stateLabel}
          </span>
        </CardTitle>
        <CardDescription className="truncate text-[11px]" title={capability?.path}>
          {subtitle}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-1 text-xs">
        <div className="flex items-center justify-between gap-2">
          <span className="text-muted-foreground">任务配置</span>
          <Badge variant="outline" className="h-4 px-1.5 text-[10px]">
            {configured}
          </Badge>
        </div>
        <div className="flex items-center justify-between gap-2">
          <span className="text-muted-foreground">作业</span>
          <span className="tabular-nums">
            {hasJobs ? `共 ${jobSummary.total} · 运行 ${jobSummary.running} · 失败 ${jobSummary.failed}` : "暂无"}
          </span>
        </div>
        {hasJobs && (
          <div className="flex items-center justify-between gap-2">
            <span className="text-muted-foreground">结果</span>
            <span className="tabular-nums">{jobSummary.results}</span>
          </div>
        )}
        {jobSummary.reason && <p className="text-[11px] text-amber-600 dark:text-amber-300">{jobSummary.reason}</p>}
      </CardContent>
    </Card>
  );
}

function CoverageRow({
  name,
  ratio,
  covered,
  planned,
}: {
  name: string;
  ratio?: number;
  covered?: number;
  planned?: number;
}) {
  return (
    <TableRow>
      <TableCell className="font-medium">{name}</TableCell>
      <TableCell className="w-36">
        <div className="flex items-center gap-2">
          <Progress value={pctValue(ratio)} className="h-1.5 w-20" />
          <span className="w-10 text-right text-xs tabular-nums">{pct(ratio)}</span>
        </div>
      </TableCell>
      <TableCell className="text-right text-xs tabular-nums">
        {typeof covered === "number" || typeof planned === "number" ? (
          <>
            {covered ?? 0} / {planned ?? 0}
          </>
        ) : (
          "—"
        )}
      </TableCell>
    </TableRow>
  );
}

function coverageRows(coverage?: AuditCoverage): {
  name: string;
  ratio?: number;
  covered?: number;
  planned?: number;
}[] {
  return [
    {
      name: "CWE",
      ratio: coverage?.cwe,
      covered: coverage?.covered_cwe,
      planned: coverage?.planned_cwe,
    },
    {
      name: "Sink 站点",
      ratio: coverage?.sink_sites,
      covered: coverage?.covered_sites,
      planned: coverage?.planned_sites,
    },
    {
      name: "模块",
      ratio: coverage?.modules,
      covered: coverage?.covered_modules,
      planned: coverage?.planned_modules,
    },
    {
      name: "入口点",
      ratio: coverage?.entry_points,
      covered: coverage?.covered_entries,
      planned: coverage?.planned_entries,
    },
  ];
}

function hypothesisSummary(hypotheses: AuditProgress["hypotheses"]): {
  counts: Record<string, number>;
  items: AuditHypothesis[];
} {
  if (!hypotheses) return { counts: {}, items: [] };
  if (Array.isArray(hypotheses)) {
    const counts: Record<string, number> = {};
    for (const hypothesis of hypotheses) {
      const status = hypothesis.status ?? "unknown";
      counts[status] = (counts[status] ?? 0) + 1;
    }
    return { counts, items: hypotheses };
  }
  return { counts: hypotheses, items: [] };
}

function candidateRowKey(candidate: AuditCandidate, index: number): string {
  return String(candidate.id ?? `${candidate.phase ?? "candidate"}-${candidate.cwe ?? ""}-${index}`);
}

function roundGate(value?: string): React.ReactNode {
  if (!value) return <span className="text-muted-foreground">—</span>;
  const passed = ["pass", "passed", "true"].includes(value.toLowerCase());
  return (
    <span className={passed ? "text-emerald-600 dark:text-emerald-400" : "text-amber-600 dark:text-amber-300"}>
      {passed ? <CheckIcon className="inline size-3" /> : <XIcon className="inline size-3" />} {label(value)}
    </span>
  );
}

function RoundsTable({ rounds }: { rounds: AuditRound[] }) {
  return (
    <div className="overflow-x-auto rounded-md border">
      <Table className="min-w-[54rem]">
        <TableHeader>
          <TableRow>
            <TableHead>轮次</TableHead>
            <TableHead className="text-right">新发现</TableHead>
            <TableHead className="text-right">累计</TableHead>
            <TableHead>Gate-C</TableHead>
            <TableHead>Gate-CWE</TableHead>
            <TableHead>Gate-H</TableHead>
            <TableHead>Gate-E</TableHead>
            <TableHead>Gate-Coverage</TableHead>
            <TableHead>决策</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rounds.map((round) => (
            <TableRow key={round.id ?? round.round}>
              <TableCell className="font-mono text-xs">R{round.round}</TableCell>
              <TableCell className="text-right tabular-nums">
                {round.new_findings ?? round.new_confirmed ?? "—"}
              </TableCell>
              <TableCell className="text-right tabular-nums">{round.total_findings ?? "—"}</TableCell>
              <TableCell className="text-xs">{roundGate(round.gate_c)}</TableCell>
              <TableCell className="text-xs">{roundGate(round.gate_cwe)}</TableCell>
              <TableCell className="text-xs">{roundGate(round.gate_h)}</TableCell>
              <TableCell className="text-xs">{roundGate(round.gate_e)}</TableCell>
              <TableCell className="text-xs">{roundGate(round.gate_coverage)}</TableCell>
              <TableCell className="text-xs">
                {DECISION_LABELS[round.decision ?? ""] ?? label(round.decision)}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

export function CodeAuditTab({ taskId, onOpenReport }: { taskId: string; onOpenReport: () => void }) {
  const [progress, setProgress] = React.useState<AuditProgress | null>(null);
  const [loaded, setLoaded] = React.useState(false);
  const [error, setError] = React.useState("");
  const [lastUpdated, setLastUpdated] = React.useState<Date | null>(null);
  const [capabilities, setCapabilities] = React.useState<AuditCapabilities | null>(null);
  const [capabilitiesLoading, setCapabilitiesLoading] = React.useState(true);
  const [downloading, setDownloading] = React.useState<"md" | "json" | null>(null);

  const loadCapabilities = React.useCallback(async () => {
    setCapabilitiesLoading(true);
    try {
      setCapabilities(await api.auditCapabilities());
    } catch {
      setCapabilities(null);
    } finally {
      setCapabilitiesLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void loadCapabilities();
  }, [loadCapabilities]);

  React.useEffect(() => {
    let active = true;
    let inFlight = false;
    const load = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const next = await api.auditProgress(taskId);
        if (!active) return;
        setProgress(next);
        setError("");
        setLastUpdated(new Date());
      } catch (err) {
        if (!active) return;
        setError((err as Error).message || "加载审计进度失败");
      } finally {
        inFlight = false;
        if (active) setLoaded(true);
      }
    };
    void load();
    const timer = setInterval(() => void load(), POLL_MS);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [taskId]);

  const downloadReport = React.useCallback(
    async (format: "md" | "json") => {
      setDownloading(format);
      try {
        await api.downloadAuditReport(taskId, format);
        toast.success(format === "md" ? "审计报告 Markdown 已下载" : "审计报告 JSON 已下载");
      } catch (err) {
        toast.error("下载失败：" + (err as Error).message);
      } finally {
        setDownloading(null);
      }
    },
    [taskId],
  );

  if (!progress && !loaded) {
    return (
      <div className="flex items-center justify-center gap-2 rounded-md border border-dashed py-20 text-sm text-muted-foreground">
        <Spinner /> 加载审计进度…
      </div>
    );
  }

  if (!progress) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center gap-3 py-16 text-center">
          <AlertTriangleIcon className="size-8 text-amber-500" />
          <div>
            <p className="text-sm font-medium">审计进度暂不可用</p>
            <p className="mt-1 max-w-xl text-xs text-muted-foreground">{error || "后端尚未建立审计会话。"}</p>
          </div>
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              setLoaded(false);
              api
                .auditProgress(taskId)
                .then((next) => {
                  setProgress(next);
                  setError("");
                  setLastUpdated(new Date());
                })
                .catch((err: Error) => setError(err.message))
                .finally(() => setLoaded(true));
            }}
          >
            <RefreshCwIcon /> 重试
          </Button>
        </CardContent>
      </Card>
    );
  }

  const session = progress.session;
  const sourceLabel =
    progress.source_label ?? session?.source_label ?? session?.source_ref ?? session?.source_type ?? "—";
  const round = session?.round ?? progress.budget?.round ?? 0;
  const maxRounds = session?.max_rounds ?? progress.budget?.max_rounds ?? 0;
  const coverage = progress.coverage;
  const rounds = progress.rounds ?? [];
  const gates = supplementRoundGates(normalizeGates(progress.gates), rounds);
  const candidates = progress.candidates ?? [];
  const hypotheses = hypothesisSummary(progress.hypotheses);
  const findings = progress.findings;
  const byVerification = findings?.by_verification ?? {};
  const phases = progress.phases ?? [];
  const sources = progress.session?.languages ?? [];
  const codegraph = summarizeEngine(progress, "codegraph");
  const codeQL = summarizeEngine(progress, "codeql");
  const joern = summarizeEngine(progress, "joern");
  const reportReady = Boolean(progress.report_ready);

  return (
    <div className="flex flex-col gap-4">
      {error && (
        <div className="flex items-center justify-between gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
          <span>刷新失败，显示上一次成功结果：{error}</span>
          <span className="shrink-0 text-muted-foreground">每 5 秒自动重试</span>
        </div>
      )}

      <Card>
        <CardHeader className="flex-row flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldCheckIcon className="size-4 text-primary" /> 代码审计概览
              <Badge variant="outline" className="text-[10px]">
                每 5 秒刷新
              </Badge>
            </CardTitle>
            <CardDescription>
              {lastUpdated ? `最近刷新：${lastUpdated.toLocaleTimeString("zh-CN", { hour12: false })}` : "等待首次刷新"}
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            {reportReady && (
              <Button size="sm" variant="outline" onClick={onOpenReport}>
                <FileTextIcon /> 查看报告
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          <SummaryItem
            label="源码"
            value={<span title={sourceLabel}>{sourceLabel}</span>}
            sub={`${session?.source_type ?? "—"}${session?.commit_sha ? ` · ${session.commit_sha.slice(0, 12)}` : ""}`}
          />
          <SummaryItem
            label="深度 / 轮次"
            value={`${session?.depth ?? progress.budget?.depth ?? "—"} · R${round}/${maxRounds || "—"}`}
            sub={sources.length > 0 ? `语言：${sources.join(" / ")}` : "语言由后端自动识别"}
          />
          <SummaryItem
            label="会话状态"
            value={<StatusPill value={session?.status} />}
            sub={`后端：${session?.backend ?? "—"}`}
          />
          <SummaryItem
            label="收敛 / 报告"
            value={progress.ready_to_complete ? "已满足收敛条件" : "审计进行中"}
            sub={
              <span className={reportReady ? "text-emerald-600 dark:text-emerald-400" : undefined}>
                {reportReady ? "报告已生成" : "报告尚未生成"}
              </span>
            }
          />
        </CardContent>
        {progress.ready_reason && (
          <CardContent className="pt-0 text-xs text-muted-foreground">{progress.ready_reason}</CardContent>
        )}
      </Card>

      <div className="grid gap-3 md:grid-cols-3">
        <EngineCard
          name="CodeGraph"
          capability={capabilities?.codegraph}
          jobSummary={codegraph}
          configured={engineConfig(progress, "codegraph")}
          loading={capabilitiesLoading}
        />
        <EngineCard
          name="CodeQL"
          capability={capabilities?.codeql}
          jobSummary={codeQL}
          configured={engineConfig(progress, "codeql")}
          loading={capabilitiesLoading}
        />
        <EngineCard
          name="Joern"
          capability={capabilities?.joern}
          jobSummary={joern}
          configured={engineConfig(progress, "joern")}
          loading={capabilitiesLoading}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <ListChecksIcon className="size-4" /> 阶段流水线
              <span className="text-xs font-normal text-muted-foreground">共 {phases.length} 项</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {phases.length === 0 ? (
              <p className="py-6 text-center text-xs text-muted-foreground">暂无阶段记录（审计可能仍在摄取源码）。</p>
            ) : (
              <div className="overflow-x-auto rounded-md border">
                <Table className="min-w-[34rem]">
                  <TableHeader>
                    <TableRow>
                      <TableHead>阶段</TableHead>
                      <TableHead>必需</TableHead>
                      <TableHead>状态</TableHead>
                      <TableHead>原因 / 门禁</TableHead>
                      <TableHead>完成时间</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {phases.map((phase, index) => (
                      <TableRow key={phase.id ?? `${phase.phase}-${index}`}>
                        <TableCell className="text-xs font-medium">{phaseLabel(phase.phase)}</TableCell>
                        <TableCell className="text-xs">{phase.required ? "是" : "否"}</TableCell>
                        <TableCell>
                          <StatusPill value={phase.status} />
                        </TableCell>
                        <TableCell className="max-w-48 whitespace-normal text-xs text-muted-foreground">
                          {phaseReason(phase)}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {fmtTime(phase.completed_at ?? phase.started_at)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <CheckIcon className="size-4" /> 门禁
              <span className="text-xs font-normal text-muted-foreground">共 {gates.length} 项</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {gates.length === 0 ? (
              <p className="py-6 text-center text-xs text-muted-foreground">暂无可展示的门禁结果。</p>
            ) : (
              <div className="flex flex-col gap-2">
                {gates.map(({ key, gate }) => (
                  <div
                    key={key}
                    className="flex flex-col gap-1 rounded-md border px-3 py-2 text-xs sm:flex-row sm:items-start sm:justify-between sm:gap-3"
                  >
                    <div className="flex min-w-0 items-center gap-2">
                      <span
                        className={cn(
                          "inline-flex size-5 shrink-0 items-center justify-center rounded-full border",
                          gate.passed ? statusTone("pass") : statusTone("retry"),
                        )}
                      >
                        {gate.passed ? <CheckIcon className="size-3" /> : <XIcon className="size-3" />}
                      </span>
                      <span className="font-medium">{gateLabel(key, gate)}</span>
                    </div>
                    <div className="min-w-0 flex-1 text-right text-muted-foreground sm:max-w-[60%]">
                      <span
                        className={
                          gate.passed ? "text-emerald-600 dark:text-emerald-400" : "text-amber-600 dark:text-amber-300"
                        }
                      >
                        {gate.passed ? "通过" : "未通过"}
                      </span>
                      {gate.reason ? ` · ${gate.reason}` : ""}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)]">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <GaugeIcon className="size-4" /> 覆盖度
            </CardTitle>
            <CardDescription>覆盖率是当前轮次的账本，不是发现数量。</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="overflow-x-auto rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>维度</TableHead>
                    <TableHead>覆盖</TableHead>
                    <TableHead className="text-right">已覆盖 / 计划</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {coverageRows(coverage).map((row) => (
                    <CoverageRow key={row.name} {...row} />
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className="flex flex-wrap gap-1.5 text-xs">
              <Badge variant="outline">非法豁免 {coverage?.invalid_exemptions ?? 0}</Badge>
              <Badge variant="outline">候选批次 {candidates.length}</Badge>
              <Badge variant="outline">发现总数 {findings?.total ?? 0}</Badge>
              {Object.entries(byVerification).map(([status, count]) => (
                <Badge key={status} variant="outline">
                  {label(status)} {count}
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <AlertTriangleIcon className="size-4 text-amber-500" /> 假设
              <span className="text-xs font-normal text-muted-foreground">
                共 {hypotheses.items.length || Object.values(hypotheses.counts).reduce((sum, n) => sum + n, 0)} 条
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(hypotheses.counts).length === 0 ? (
                <span className="text-xs text-muted-foreground">暂无假设记录。</span>
              ) : (
                Object.entries(hypotheses.counts).map(([status, count]) => (
                  <Badge key={status} variant="outline">
                    {label(status)} {count}
                  </Badge>
                ))
              )}
            </div>
            {hypotheses.items.slice(0, 6).map((hypothesis, index) => (
              <div
                key={hypothesis.id ?? `${hypothesis.hypothesis_key ?? "h"}-${index}`}
                className="rounded-md border px-2.5 py-1.5 text-xs"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="min-w-0 flex-1 truncate font-medium" title={hypothesis.statement}>
                    {hypothesis.statement || hypothesis.hypothesis_key || "未命名假设"}
                  </span>
                  <StatusPill value={hypothesis.status} />
                </div>
                {hypothesis.evidence && (
                  <p className="mt-1 line-clamp-2 text-muted-foreground" title={hypothesis.evidence}>
                    {hypothesis.evidence}
                  </p>
                )}
              </div>
            ))}
            {hypotheses.items.length > 6 && (
              <p className="text-xs text-muted-foreground">仅显示前 6 条，共 {hypotheses.items.length} 条。</p>
            )}
          </CardContent>
        </Card>
      </div>

      {rounds.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <RefreshCwIcon className="size-4" /> 轮次历史
            </CardTitle>
          </CardHeader>
          <CardContent>
            <RoundsTable rounds={rounds} />
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <ShieldCheckIcon className="size-4" /> 候选批次
            <span className="text-xs font-normal text-muted-foreground">共 {candidates.length} 批</span>
          </CardTitle>
          <CardDescription>候选批次由阶段/CWE/模块聚合，实际派发以审计导演为准。</CardDescription>
        </CardHeader>
        <CardContent>
          {candidates.length === 0 ? (
            <p className="py-6 text-center text-xs text-muted-foreground">暂无候选批次。</p>
          ) : (
            <div className="overflow-x-auto rounded-md border">
              <Table className="min-w-[40rem]">
                <TableHeader>
                  <TableRow>
                    <TableHead>阶段</TableHead>
                    <TableHead>CWE</TableHead>
                    <TableHead>模块</TableHead>
                    <TableHead className="text-right">Sink</TableHead>
                    <TableHead className="text-right">发现</TableHead>
                    <TableHead className="text-right">优先级</TableHead>
                    <TableHead>严重度</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {candidates.map((candidate, index) => (
                    <TableRow key={candidateRowKey(candidate, index)}>
                      <TableCell className="text-xs">{phaseLabel(candidate.phase)}</TableCell>
                      <TableCell className="font-mono text-xs">{candidate.cwe || "—"}</TableCell>
                      <TableCell className="max-w-48 truncate font-mono text-xs" title={candidate.module}>
                        {candidate.module || candidate.language || "—"}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{candidate.sink_keys?.length ?? 0}</TableCell>
                      <TableCell className="text-right tabular-nums">{candidate.finding_ids?.length ?? 0}</TableCell>
                      <TableCell className="text-right tabular-nums">{candidate.priority ?? "—"}</TableCell>
                      <TableCell className="text-xs">
                        {SEVERITY_LABELS[candidate.severity ?? ""] ?? label(candidate.severity)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex-row flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2 text-sm">
              <FileTextIcon className="size-4" /> 审计报告
            </CardTitle>
            <CardDescription>
              {reportReady
                ? "报告已生成，可下载 Markdown 或 JSON；也可以在“报告”页签中预览。"
                : "审计收敛并生成报告后，可在此下载。"}
            </CardDescription>
          </div>
          <div className="flex flex-wrap gap-2">
            {reportReady ? (
              <>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={downloading !== null}
                  onClick={() => void downloadReport("md")}
                >
                  {downloading === "md" ? <Spinner /> : <DownloadIcon />} Markdown
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={downloading !== null}
                  onClick={() => void downloadReport("json")}
                >
                  {downloading === "json" ? <Spinner /> : <DownloadIcon />} JSON
                </Button>
                <Button size="sm" onClick={onOpenReport}>
                  预览报告
                </Button>
              </>
            ) : (
              <Button size="sm" variant="outline" onClick={onOpenReport}>
                打开报告页签
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid gap-2 text-xs sm:grid-cols-3">
            <div className="rounded-md border px-2.5 py-2">
              <div className="text-muted-foreground">报告状态</div>
              <div className="mt-0.5 font-medium">{reportReady ? "已生成" : "未生成"}</div>
            </div>
            <div className="rounded-md border px-2.5 py-2">
              <div className="text-muted-foreground">候选验证</div>
              <div className="mt-0.5 font-medium">
                已确认 {(byVerification.confirmed ?? 0) + (findings?.confirmed ?? 0)} · 待验证{" "}
                {(byVerification.candidate ?? 0) + (byVerification.unverified ?? 0) + (findings?.candidate ?? 0)}
              </div>
            </div>
            <div className="rounded-md border px-2.5 py-2">
              <div className="text-muted-foreground">报告地址</div>
              <div className="mt-0.5 truncate font-mono text-[11px]" title={progress.report_url}>
                {progress.report_url || "—"}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

# ARTEX 代码审计使用说明

本文说明 ARTEX 新增的 `code_audit` 任务模式：如何创建任务、输入源码、安装分析引擎、阅读审计进度/报告，以及当前安全边界和已知限制。

设计文档：`docs/superpowers/specs/2026-10-26-artex-code-audit-fusion-design.md`
实现计划：`docs/superpowers/plans/2026-10-26-artex-code-audit-core.md`

---

## 1. 能力概览

代码审计任务在 ARTEX 原有任务/探索图/planner/worker 调度上运行：

- **源码获取**：Git URL、服务器本地目录、上传 zip。
- **确定性审计导演**：快照、语言/框架画像、CWE 计划、sink 预扫描、覆盖度台账、质量门禁、轮次与报告。
- **受限审计 worker**：只拥有只读代码分析工具 + 结构化写回工具；没有 Bash、网络、源码写入、部署或构建工具。
- **CodeGraph**：符号、调用链、源码探索的主要底座。
- **CodeQL**：数据流/污点查询（可选；需要 CLI + query packs）。
- **Joern**：CPG/CFG/可达性查询（可选；需要 CLI，默认模板查询）。
- **Worker 后端**：默认使用 ARTEX 内置静态 worker；可选 Codex / OpenCode / Claude Code / Cursor / Pi / 自定义 CLI。
- **结构化证据**：source→sink trace、sanitizer、S0–S5 语义链、可达性、引擎命中、PoC artifact（不执行）。
- **确定性报告**：Markdown + JSON，包含覆盖度、门禁、发现、假设、引擎缺口和限制。

静态阶段**不执行目标代码**，不构建、不运行目标服务、不执行 PoC。

---

## 2. 创建任务

在任务页选择“代码审计”模式，填写：

| 字段 | 说明 |
|---|---|
| 源类型 | Git URL / 本地目录 / 上传压缩包 |
| Git URL / ref | 只允许 https/ssh/scp-like；可指定分支/tag/commit |
| 本地目录 | 必须位于 `ARTEX_AUDIT_LOCAL_ROOTS` 允许的根目录下 |
| zip | 通过上传控件暂存，提交 draft id 作为 `upload_id` |
| 深度 | quick/standard/deep，默认 deep |
| CWE 范围 | core（26 项）/ full（注册表全量）/ explicit（手填） |
| 语言 | 可选；留空自动识别 |
| 最大轮次 | 1–10；门禁失败自动补扫，连续两轮零新增收敛，达到上限生成部分报告 |
| 引擎 | CodeGraph（required/auto/off）、CodeQL（auto/off）、Joern（auto/off） |
| Worker 后端 | builtin（默认）/ codex / opencode / claudecode / cursor / pi / custom |
| 预算 | 高级参数可留空使用默认值 |

API 示例：

```json
POST /api/tasks
{
  "name": "订单服务审计",
  "description": "订单服务 Java 审计",
  "goal": "",
  "task_mode": "code_audit",
  "audit": {
    "source_type": "git",
    "repo_url": "https://example.com/order-service.git",
    "ref": "main",
    "depth": "deep",
    "cwe_scope": "core",
    "max_rounds": 1,
    "engines": {"codegraph": "required", "codeql": "auto", "joern": "auto"},
    "worker": {
      "backend": "codex",
      "mode": "privileged",
      "command": "codex",
      "args": ["exec", "--dangerously-bypass-approvals-and-sandbox", "--output-schema", "{{schema_file}}", "--output-last-message", "{{output_file}}", "{{input_file}}"],
      "cwd": "{{workspace}}",
      "timeout_seconds": 3600
    }
  }
}
```

`goal` 留空时后端生成“完成对 <源> 的全量深度代码审计”。

### Worker 后端与权限

默认不配置 `worker` 时使用内置静态 worker，保持只读代码分析和结构化写回边界。外部 CLI worker 通过 argv 启动，不支持 shell 拼接；参数每行一个，占位符包括 `{{task_id}}`、`{{intent_id}}`、`{{workspace}}`、`{{snapshot_root}}`、`{{input_file}}`、`{{output_file}}`、`{{schema_file}}`。

高权限模式必须显式确认。它允许外部 CLI 使用自带的 Bash、文件、网络和本地工具能力；ARTEX 不提供沙箱隔离、凭据隔离或动作级审计。外部结果按 `candidate` 入库，不会自动确认。

创建页会调用 `GET /api/worker-backends` 获取后端、建议命令、可用性和权限模式。命令模板只是起点，不同 CLI 版本可能需要调整。

---

## 3. 安装分析引擎

### CodeGraph（推荐/deep 必需）

```bash
npm install -g @colbymchenry/codegraph
codegraph --version
```

ARTEX 会在任务快照上执行 `codegraph init`/`index`，并通过 stdio MCP 启动 `codegraph serve --mcp -p <snapshot>`。可用环境变量覆盖二进制：

```bash
export ARTEX_CODEGRAPH_BIN=/path/to/codegraph
```

### CodeQL（可选）

1. 安装 CodeQL CLI。当前模板已用 CodeQL 2.27.3 验证。
2. 安装与 CLI 匹配的语言 query packs（`*-all` 会带齐传递依赖）：

```bash
codeql pack download codeql/java-all@9.2.0
codeql pack download codeql/python-all@7.2.8
codeql pack download codeql/javascript-all@2.10.4
```

3. 配置：

```bash
export ARTEX_CODEQL_BIN=/path/to/codeql
# 如 packs 不在默认 ~/.codeql/packages，可设置为包含 codeql/ 目录的缓存根
export ARTEX_CODEQL_SEARCH_PATH=/path/to/packages
```

ARTEX 会读取本地语言 pack 的 `qlpack.yml`，在任务工作目录生成 `codeql-pack.lock.yml`，固定语言 pack 及传递依赖版本，并把精确版本目录传给 CodeQL；这可以避免本机缓存同时存在多个依赖版本时 CodeQL 拒绝解析。缺少本地依赖时会报告引擎能力缺口，不会自动下载或执行目标构建。

安全约束：

- 只使用 `--build-mode=none`（Java/Kotlin、JS/TS、Python、Ruby、C#）或操作者提供的预构建数据库。
- C/C++、Go 需要构建的 CodeQL 数据库**不会在静态阶段自动构建**；未提供预构建库时记录为能力缺口。
- 需要 query pack 与许可证；缺失时任务继续，报告披露引擎缺口。

### Joern（可选）

1. 安装 Joern CLI（含 `joern` 与 `joern-parse`，需要 JDK 17；当前模板已用 Joern 4.0.535 验证）。
2. 配置：

```bash
export ARTEX_JOERN_BIN=/path/to/joern
export ARTEX_JOERN_PARSE_BIN=/path/to/joern-parse
# 可选：沙箱命令（未配置时只允许模板查询）
export ARTEX_JOERN_SANDBOX="docker run --rm ..."
```

Windows 必须使用发行版自带的 `.bat` 启动器；ARTEX 会自动优先解析 `joern.bat`/`joern-parse.bat`，也可显式设置上述环境变量。运行前建议：

```powershell
$env:JAVA_HOME = "D:\path\to\jdk-17"
```

安全约束：

- 只解析源码生成 CPG，不构建/不运行目标。
- 默认只执行 ARTEX 模板生成的 CPGQL；自由查询需要沙箱 + 查询词法校验。
- Joern taint 模板按语言选择数据流终点：Java/JS/TS/C++ 使用 sink call，Python/C/Go 使用 sink call argument；sanitizer 与 path/exclude scope 会进入模板过滤。
- 未安装/解析失败时记录为引擎缺口，不阻塞 CodeGraph/预扫描。

---

## 4. 本地目录允许根

本地目录审计必须显式授权根目录：

```bash
export ARTEX_AUDIT_LOCAL_ROOTS="/srv/code,/data/repos"
```

多个根用逗号或分号分隔。未配置时本地目录任务会失败并提示。ARTEX 会把源码快照复制到任务工作区，不修改原目录。

---

## 5. 审计流程与阅读方式

1. **S0 摄取**：源码获取、快照、语言画像、CodeGraph/CodeQL/Joern 准备、sink 预扫描。
2. **S1 画像 / S2 攻击面**：模块、信任边界、入口点、接口。
3. **S3 数据流 / S4 检测**：入口点与 sink site 批量派发；预扫描 + CodeQL/Joern 结果合并为候选站点。
4. **S5–S10 深链**：验证、逻辑/合规、深析、设计验证、深度放大与非执行 PoC；worker 复核 source→sink、sanitizer、替代路径并写回结论。
5. **完成/报告**：覆盖度与门禁通过（或达到强制收敛/无候选）后生成报告；`prove_goal` 仅在报告就绪后允许任务完成。

### 自由目标与 LLM 辅助意图

创建任务时可以把关注点写进 `goal`，例如 `重点看文件上传和 SSRF` 或 `重点看解码器错误状态处理`。预扫描得到语言/CWE 白名单后，ARTEX 会通过任务 LLM 链调用固定提示词（`v2`），把自由目标转换成结构化 `DetectionIntent`：

- 只接受 JSON schema 内的 IR 字段；语言、CWE、引擎、scope、pattern、query kind 都必须通过白名单/结构校验。
- 最多执行 1 次初始调用 + 2 次修复；仍失败则保留确定性 sink 规则意图并记录 query gap。
- LLM 不输出 CodeQL/CPGQL 原生查询；查询文本仍由 ARTEX 模板渲染，后续交给引擎校验/执行。
- `v2` 额外支持语义 query kind：`error_contract`（错误契约）、`state_transition`（状态迁移）和 `invariant`（不变式）。这些意图会主动覆盖攻击面、返回值/错误码分类、永久错误与临时可恢复状态、宏展开、调用方契约、固定大小缓冲、重试循环和不变式假设。
- 语义意图在 CodeGraph 可用时强制只派发给 CodeGraph，渲染为调查清单和证明链/反证要求，不会退回 source→sink 话术，也不会把 LLM 输出当作 CodeQL/CPGQL 执行。
- worker 系统提示词包含审计方法论：入口点与攻击者可控输入、状态机与错误契约、宏展开、调用方契约、重试循环、固定大小缓冲、证明链和反证。
- 报告和 `audit_sessions.engines` 记录识别来源（`llm`/`fallback`）、模型、提示词版本、原始输出 SHA-256、修复次数和缺口。
- 渲染后的查询缓存 key 包含引擎版本、语言、源码 commit、意图 IR hash 和模板版本，避免二进制升级或新 commit 复用旧结果。

任务详情的“代码审计”页签展示：

- 源信息（脱敏）、深度、状态、轮次。
- 引擎状态（CodeGraph/CodeQL/Joern 可用性、版本、缺口）。
- 引擎查询与缺口：最近作业状态、query hash、结果数、耗时、错误，以及意图识别 provenance/query gap。
- 覆盖缺口钻取：planned/missed/exempt 行、位置、原因与未覆盖 CWE，前端表格直接展示。
- 候选批次多选与批量验证：可把候选 finding 批量标记为已确认、已反驳或设计意图，必须填写复核证据。
- 阶段表、覆盖度、门禁、候选批次、假设、报告下载。
- 报告页签显示 Markdown 报告并支持鉴权下载；发现详情展示结构化代码证据，源码查看器按起止行区间高亮。
- 任务模板管理可选择任务模式并编辑代码审计 `audit_config`；渗透测试模板不携带审计配置。

API：

```text
GET /api/tasks/{id}/audit/progress
GET /api/tasks/{id}/audit/report?format=md|json
POST /api/tasks/{id}/audit/findings/verification-batch
GET /api/tasks/{id}/audit/source/file?path=<rel>&line=<n>
GET /api/audit/capabilities
GET /api/worker-backends
```

批量验证接口只接受当前任务内仍处于 `candidate`/`unverified` 的 finding，结论限 `confirmed`/`refuted`/`design_intent`，`evidence` 必填且单次最多 200 条。示例：

```json
{
  "finding_ids": [18, 19],
  "verification": "confirmed",
  "evidence": "manual review source-to-sink proof"
}
```

---

## 6. 证据与报告

代码 finding 的核心字段：

- `cwe_id`、`title`、`severity`、`confidence`、`verification`。
- `location`（path/line/symbol）、`source`、`sink`、`trace`。
- `sanitizers`（present/missing/insufficient）。
- `semantic_chain`（S0–S5 编码/类型/路径/协议/序列化转换）。
- `reachability`、`preconditions`、`impact`、`poc`（artifact 路径，`executed=false`）。
- `engines`（CodeQL/Joern 命中与原始引用）。

报告为确定性 Markdown + JSON，包含：摘要、范围/方法、严重度/CWE 统计、发现明细、覆盖度缺口、假设、门禁、引擎状态、限制。Gate-H 会检查 findings 必须有可追溯假设、尝试次数纪律和连续反驳后的 pivot；评分低于 70 时报告给出 warning 但不单独阻断。报告不包含源码快照绝对路径或凭据。

---

## 7. 安全边界

- 审计 worker 的最终工具列表是代码层固定白名单；不使用 `ToolAugment`/DB 绑定注入 MCP/skill/shell 工具。
- 禁用 SDK 后台任务工具（`Monitor`/`TaskOutput`/`TaskStop`/`TaskList`）；禁用 Bash/Read/Write/Edit/WebFetch/WebSearch。
- 目标源码视为不可信数据；只读快照；不执行目标代码/构建/测试/CI/hook/postinstall。
- 所有源码/产物路径限制在任务快照/artifact 目录；zip 防穿越/炸弹；Git 禁凭据/hook/子模块。
- CodeQL 只用 build-mode none 或预构建 DB；Joern 只解析。
- 引擎 stderr/事件错误先截断再脱敏绝对路径、userinfo、Bearer、secret assignment、云 key 与私钥；报告使用同类 DLP。
- CodeQL 分析默认 2 线程、4096 MB RAM，可通过预算 `codeql_threads`（1–16）与 `codeql_ram_mb`（512–32768）配置；引擎查询作业默认串行，可用 `engine_concurrency`（1–4）提高并发；Joern 默认模板查询，可选 `ARTEX_JOERN_SANDBOX_CMD`，并受 `max_engine_seconds` 与输出上限约束。
- 外部 CLI worker 的 `mode=privileged` 会突破静态审计边界；只应在可信主机、可信登录态和可接受审计风险时启用。
- LLM 意图分析只产出受限 `DetectionIntent` IR；严格拒绝 `query_text`/`query`/`codeql`/`cpgql` 等原生查询字段。
- 引擎/查询失败显式记录；不会静默当作“没有漏洞”。

---

## 8. 当前限制（M1）

- **仅静态审计**：不部署、不执行 PoC、不做动态流量验证。
- **深链质量待抽样**：多轮聚焦补扫/收敛与 S3–S10 调度链路已实现；真实 LLM deep 任务的阶段质量、误报与召回仍需专项基准。
- **多引擎模板覆盖**：CodeQL 的 Java、Python、JavaScript、TypeScript taint/sink 模板已在 CodeQL 2.27.3 上真实建库、编译、分析并命中；Go/C/C++ 仅支持操作者提供预构建数据库，其他语言/查询类型会报告能力缺口。Joern 的 Java、Python、JavaScript、TypeScript、Go、C、C++ taint/sink 均已在 Joern 4.0.535 上真实 parse、执行并命中；模板已应用 sanitizer 与 path/exclude scope。
- **真实引擎验证**：CodeQL/Joern 适配器有 fake/fixture 测试和可选的 live 测试；具体安装、query pack、Java 版本差异可能导致模板需要调整。Windows 下 Joern 需要 JDK 17 和 `.bat` 启动器，建议显式设置 `ARTEX_JOERN_BIN`/`ARTEX_JOERN_PARSE_BIN`。
- **不做真正的符号级 taint 引擎**：ARTEX 的检测以 CodeGraph 探索 + 引擎查询 + worker 复核为主；引擎结果不会自动确认。
- **归档**：`code_audit` 任务支持 format v4 归档/恢复，包含审计七表与报告；恢复后任务保持暂停，不自动启动渗透逻辑。

---

## 9. 开发/测试

```bash
cd ARTEX
go test ./audit/... -count=1
go test ./agent -run 'TestAudit' -count=1
go test ./db -run 'TestAudit|TestCodeFinding' -count=1   # 需要 PG
go test ./server -run 'TestCreateTask|TestAudit|TestGoal|TestAuditEngine' -count=1
go build ./...
go vet ./audit/... ./agent ./db ./server
```

真实引擎测试（需要安装对应 CLI）：

```bash
# CodeQL
ARTEX_ENGINE_INTEGRATION=1 go test ./audit/engines -run 'TestRealCodeQL' -count=1 -timeout=15m
# Joern
ARTEX_ENGINE_INTEGRATION=1 go test ./audit/engines -run 'TestRealJoern' -count=1 -timeout=15m
```

数据库测试需要 `ARTEX_PG_DSN` 或 `config.json`；未配置时相关测试会 skip。

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
| 最大轮次 | 1–10；M1 目前固定单轮，见限制 |
| 引擎 | CodeGraph（required/auto/off）、CodeQL（auto/off）、Joern（auto/off） |
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
    "engines": {"codegraph": "required", "codeql": "auto", "joern": "auto"}
  }
}
```

`goal` 留空时后端生成“完成对 <源> 的全量深度代码审计”。

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

1. 安装 CodeQL CLI。
2. 安装语言 query packs（示例）：

```bash
codeql pack download codeql/java-all codeql/java-queries
codeql pack download codeql/python-all codeql/python-queries
codeql pack download codeql/javascript-all codeql/javascript-queries
```

3. 配置：

```bash
export ARTEX_CODEQL_BIN=/path/to/codeql
# 如 packs 不在默认 ~/.codeql/packages，可设置搜索路径
export ARTEX_CODEQL_SEARCH_PATH=/path/to/packs
```

安全约束：

- 只使用 `--build-mode=none`（Java/Kotlin、JS/TS、Python、Ruby、C#）或操作者提供的预构建数据库。
- C/C++、Go 需要构建的 CodeQL 数据库**不会在静态阶段自动构建**；未提供预构建库时记录为能力缺口。
- 需要 query pack 与许可证；缺失时任务继续，报告披露引擎缺口。

### Joern（可选）

1. 安装 Joern CLI（含 `joern` 与 `joern-parse`，需要 Java 17+）。
2. 配置：

```bash
export ARTEX_JOERN_BIN=/path/to/joern
export ARTEX_JOERN_PARSE_BIN=/path/to/joern-parse
# 可选：沙箱命令（未配置时只允许模板查询）
export ARTEX_JOERN_SANDBOX="docker run --rm ..."
```

安全约束：

- 只解析源码生成 CPG，不构建/不运行目标。
- 默认只执行 ARTEX 模板生成的 CPGQL；自由查询需要沙箱 + 查询词法校验。
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
3. **S4 检测**：按 CWE/语言批量派发 sink site 意图；预扫描 + CodeQL/Joern 结果合并为候选站点。
4. **S5 验证**：worker 复核 source→sink、sanitizer、替代路径；写回 confirmed/refuted/design_intent。
5. **完成/报告**：覆盖度与门禁通过（或达到强制收敛/无候选）后生成报告；`prove_goal` 仅在报告就绪后允许任务完成。

任务详情的“代码审计”页签展示：

- 源信息（脱敏）、深度、状态、轮次。
- 引擎状态（CodeGraph/CodeQL/Joern 可用性、版本、缺口）。
- 阶段表、覆盖度、门禁、候选批次、假设、报告下载。
- 报告页签显示 Markdown 报告；发现详情展示结构化代码证据。

API：

```text
GET /api/tasks/{id}/audit/progress
GET /api/tasks/{id}/audit/report?format=md|json
GET /api/tasks/{id}/audit/source/file?path=<rel>&line=<n>
GET /api/audit/capabilities
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

报告为确定性 Markdown + JSON，包含：摘要、范围/方法、严重度/CWE 统计、发现明细、覆盖度缺口、假设、门禁、引擎状态、限制。报告不包含源码快照绝对路径或凭据。

---

## 7. 安全边界

- 审计 worker 的最终工具列表是代码层固定白名单；不使用 `ToolAugment`/DB 绑定注入 MCP/skill/shell 工具。
- 禁用 SDK 后台任务工具（`Monitor`/`TaskOutput`/`TaskStop`/`TaskList`）；禁用 Bash/Read/Write/Edit/WebFetch/WebSearch。
- 目标源码视为不可信数据；只读快照；不执行目标代码/构建/测试/CI/hook/postinstall。
- 所有源码/产物路径限制在任务快照/artifact 目录；zip 防穿越/炸弹；Git 禁凭据/hook/子模块。
- CodeQL 只用 build-mode none 或预构建 DB；Joern 只解析。
- 引擎/查询失败显式记录；不会静默当作“没有漏洞”。

---

## 8. 当前限制（M1）

- **仅静态审计**：不部署、不执行 PoC、不做动态流量验证。
- **M1 固定单轮**：多轮聚焦补扫/收敛策略尚未实现；覆盖不足或引擎缺口时可能生成 `done_with_gaps` 部分报告。
- **多引擎模板覆盖有限**：CodeQL 的 Java taint/sink 模板已在 CodeQL 2.25.5 上真实编译、建库、分析并命中；当前 Python/JS/TS 模板因本机 query pack 不可用/清单不兼容未注册，其他语言/查询类型会报告能力缺口。Joern 的 Java taint/sink 已在 Joern 4.0.535 上真实解析 CPG、执行并命中；Python/JS/TS/Go/C/C++ 模板已注册但尚未逐一真实验证，且 Joern 模板不应用 sanitizer/path-scope 过滤。
- **真实引擎验证**：CodeQL/Joern 适配器有 fake/fixture 测试和可选的 live 测试；具体安装、query pack、Java 版本差异可能导致模板需要调整。Windows 下 Joern 需要 JDK 17 和 `.bat` 启动器，建议显式设置 `ARTEX_JOERN_BIN`/`ARTEX_JOERN_PARSE_BIN`。
- **不做真正的符号级 taint 引擎**：ARTEX 的检测以 CodeGraph 探索 + 引擎查询 + worker 复核为主；引擎结果不会自动确认。
- **归档**：`code_audit` 任务当前拒绝归档；审计表尚未纳入归档格式。

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

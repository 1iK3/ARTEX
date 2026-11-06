# Kali 审计镜像部署与使用指南

本文覆盖 `Dockerfile.kali-audit` 构建的完整审计运行时：ARTEX 后端与前端、Kali 工具链、CodeGraph / CodeQL / Joern、Codex / OpenCode / Claude Code、sapper-v2、CTF skills，以及首次启动即初始化的干净 PostgreSQL 数据库。

## 1. 前置条件

- Docker 24+，建议预留 25GB 以上磁盘空间；镜像约 9.6GB，解压和构建缓存需要额外空间。
- Docker Compose v2 插件或 v1 均可；下文优先使用 `docker compose`，旧环境可替换为 `docker-compose`。
- 端口：`8787`（Web/API）、`8788`（代理，仅绑定本机）。
- 至少配置一个可用 LLM 凭据：Codex/OpenCode 登录态或 `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`。

## 2. 构建镜像

在仓库根目录执行：

```bash
git clone https://github.com/1iK3/ARTEX.git
cd ARTEX
git checkout feat/code-audit

docker build --pull \
  -f Dockerfile.kali-audit \
  -t artex-kali-audit:feat-code-audit-v3 \
  .
```

如果环境缺少 Buildx，改用经典构建器：

```bash
DOCKER_BUILDKIT=0 docker build \
  -f Dockerfile.kali-audit \
  -t artex-kali-audit:feat-code-audit-v3 \
  .
```

PowerShell 写法：

```powershell
$env:DOCKER_BUILDKIT = "0"
docker build -f Dockerfile.kali-audit -t artex-kali-audit:feat-code-audit-v3 .
```

常用构建参数：

```bash
docker build \
  -f Dockerfile.kali-audit \
  -t artex-kali-audit:feat-code-audit-v3 \
  --build-arg NPM_REGISTRY=https://registry.npmjs.org \
  --build-arg GOPROXY=https://proxy.golang.org,direct \
  --build-arg GITHUB_PROXY= \
  --build-arg CTF_SUPER_HUB_REF=7715719738578b36b0a84b74aeb0de41bda0eaae \
  --build-arg CTF_SKILLS_REF=aabc3ef61db9231ba7005e90b11c7b9bcde410f9 \
  .
```

`ctf-super-hub` 与 `ctf-skills` 会在构建时从 GitHub 拉取固定 commit，不依赖仓库里的本地拷贝；更新时请同步修改 `Dockerfile.kali-audit` 中的默认 ref。

## 3. 启动与验证

```bash
mkdir -p workspaces
docker compose -f docker-compose.kali-audit.yml up -d
docker compose -f docker-compose.kali-audit.yml ps
curl -fsS http://127.0.0.1:8787/api/health
```

浏览器访问：

```text
http://127.0.0.1:8787
```

查看日志：

```bash
docker compose -f docker-compose.kali-audit.yml logs -f artex-kali-audit
```

## 4. 数据与持久化

| 容器路径 | Compose 卷 | 用途 |
|---|---|---|
| `/app/data` | `artex-data` | ARTEX 应用数据、JWT、worker 配置 |
| `/var/lib/postgresql/data` | `artex-pgdata-clean` | 内置 PostgreSQL 数据库 |
| `/workspaces` | `./workspaces` | 目标代码、CTF 附件、审计工作区 |

镜像在构建阶段初始化了一份已应用 schema 的 PostgreSQL 数据目录。第一次使用空的 `artex-pgdata-clean` 卷时，Docker 会把这份干净数据库复制进卷；后续重启、重建容器都会保留数据。

默认内置数据库连接串：

```text
postgres://artex:artex@127.0.0.1:5432/artex?sslmode=disable
```

可通过环境变量覆盖账号、密码、库名和端口：

```bash
POSTGRES_USER=artex
POSTGRES_PASSWORD=change-me
POSTGRES_DB=artex
POSTGRES_PORT=5432
```

如果使用外部 PostgreSQL，在 `.env` 或环境中设置 `ARTEX_PG_DSN`，入口脚本会跳过内置 PostgreSQL：

```bash
ARTEX_PG_DSN=postgres://user:password@host:5432/artex?sslmode=disable
docker compose -f docker-compose.kali-audit.yml up -d
```

外部数据库需要能被容器访问，且连接账号需要有执行 `db/schema.sql` 的权限。ARTEX 启动时会幂等执行 schema 初始化。

## 5. Codex 与 OpenCode worker 配置

### API Key 方式

`docker-compose.kali-audit.yml` 已透传以下变量：

```bash
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
ARTEX_LLM_PROVIDER=...
ARTEX_LLM_MODEL=...
ARTEX_LLM_BASE_URL=...
ARTEX_LLM_PROXY=...
```

在任务创建页选择 Codex 或 OpenCode 作为 worker，或通过代码审计 API 的 `audit.worker` 配置指定。

### 复用宿主机登录态

入口脚本会把以下运行时目录链接到 `/app/data/.worker-config`，使登录态和 skill 配置在容器重建后仍保留：

```text
/app/data/.worker-config/codex                -> /root/.codex
/app/data/.worker-config/opencode/config      -> /root/.config/opencode
/app/data/.worker-config/opencode/data        -> /root/.local/share/opencode
```

Linux / WSL 宿主机示例：

```bash
cid="$(docker compose -f docker-compose.kali-audit.yml ps -q artex-kali-audit)"

docker compose -f docker-compose.kali-audit.yml exec artex-kali-audit \
  mkdir -p /app/data/.worker-config/codex \
           /app/data/.worker-config/opencode/config \
           /app/data/.worker-config/opencode/data

docker cp "$HOME/.codex/." "$cid:/app/data/.worker-config/codex/"
docker cp "$HOME/.config/opencode/." "$cid:/app/data/.worker-config/opencode/config/"
docker cp "$HOME/.local/share/opencode/." "$cid:/app/data/.worker-config/opencode/data/"

docker compose -f docker-compose.kali-audit.yml restart artex-kali-audit
```

Windows PowerShell 示例：

```powershell
$cid = docker compose -f docker-compose.kali-audit.yml ps -q artex-kali-audit
docker compose -f docker-compose.kali-audit.yml exec artex-kali-audit mkdir -p `
  /app/data/.worker-config/codex `
  /app/data/.worker-config/opencode/config `
  /app/data/.worker-config/opencode/data

docker cp "$env:USERPROFILE\.codex\." "${cid}:/app/data/.worker-config/codex/"
docker cp "$env:USERPROFILE\.config\opencode\." "${cid}:/app/data/.worker-config/opencode/config/"
docker cp "$env:USERPROFILE\.local\share\opencode\." "${cid}:/app/data/.worker-config/opencode/data/"

docker compose -f docker-compose.kali-audit.yml restart artex-kali-audit
```

也可以先创建上述目录并重启容器，再在容器内登录：

```bash
docker compose -f docker-compose.kali-audit.yml exec artex-kali-audit codex login
docker compose -f docker-compose.kali-audit.yml exec artex-kali-audit opencode auth login
```

验证 CLI：

```bash
docker compose -f docker-compose.kali-audit.yml exec artex-kali-audit codex --version
docker compose -f docker-compose.kali-audit.yml exec artex-kali-audit opencode --version
```

高权限 worker 会启用外部 CLI 自带的 Bash、文件、网络与本地工具能力。ARTEX 不为它提供额外沙箱、凭据隔离或动作级审计；只应在可信目标、可信登录态和接受审计风险时使用。

## 6. CTF skills

镜像内置：

- `ctf-skills`：12 个分类 skill，安装到 `/root/.agents/skills`。
- `ctf-super-hub`：固定 commit 保存到 `/opt/ctf-super-hub`，首次启动复制到 `/root/.codex/skills` 和 `/root/.config/opencode/skills`。

由于 Codex / OpenCode 配置目录被持久化到 `/app/data/.worker-config`，首次启动安装后的 skills 也会随卷保留。

验证：

```bash
docker compose -f docker-compose.kali-audit.yml exec artex-kali-audit \
  bash -lc 'find /root/.agents/skills -mindepth 2 -maxdepth 2 -name SKILL.md | wc -l'

docker compose -f docker-compose.kali-audit.yml exec artex-kali-audit \
  bash -lc 'test -f /root/.codex/skills/ctf-super-hub/SKILL.md && echo codex-ok'

docker compose -f docker-compose.kali-audit.yml exec artex-kali-audit \
  bash -lc 'test -f /root/.config/opencode/skills/ctf-super-hub/SKILL.md && echo opencode-ok'
```

## 7. sapper-v2

镜像已内置 `/usr/local/bin/sapper`。默认通过 `codex-wrapper` 把 sapper 的 agent 调用转发到 Codex CLI：

```text
SAPPER_BIN=codex-wrapper
SAPPER_MODEL=deepseek-v4.1-flash
SAPPER_ROOT=/workspaces
```

进入容器后可按项目方式运行：

```bash
docker compose -f docker-compose.kali-audit.yml exec artex-kali-audit bash
cd /workspaces/my-case

sapper setup --goal "assess http://target" --agents
sapper status
sapper dispatch reason
sapper auto --skip-permissions --verify
```

更换模型：

```bash
SAPPER_MODEL=your-model sapper auto --skip-permissions
```

完整命令、图模型和安全注意事项见 [`docker/kali-audit/sapper-v2/README.zh-CN.md`](../docker/kali-audit/sapper-v2/README.zh-CN.md)。

## 8. 导入与导出镜像

导出：

```bash
docker save artex-kali-audit:feat-code-audit-v3 \
  -o artex-kali-audit-feat-code-audit-v3.tar

sha256sum artex-kali-audit-feat-code-audit-v3.tar \
  > artex-kali-audit-feat-code-audit-v3.tar.sha256
```

导入：

```bash
docker load -i artex-kali-audit-feat-code-audit-v3.tar
docker compose -f docker-compose.kali-audit.yml up -d
```

不用 Compose 时可直接运行：

```bash
docker run -d --name artex-kali-audit \
  -p 8787:8787 \
  -p 127.0.0.1:8788:8788 \
  -v artex-data:/app/data \
  -v artex-pgdata-clean:/var/lib/postgresql/data \
  -v "$PWD/workspaces:/workspaces" \
  --restart unless-stopped \
  artex-kali-audit:feat-code-audit-v3
```

## 9. 重置干净数据库

只重置 PostgreSQL：

```bash
docker compose -f docker-compose.kali-audit.yml down
docker volume ls --format '{{.Name}}' | grep artex-pgdata-clean
docker volume rm artex_artex-pgdata-clean
docker compose -f docker-compose.kali-audit.yml up -d
```

如果卷名前缀不同，请使用上一步 `grep` 输出的实际名称。`docker compose down -v` 会同时删除 `artex-data` 与 PostgreSQL 卷，适合完全初始化，但会丢失应用数据与 worker 登录态。

## 10. 常见问题

- **健康检查失败**：先看 `docker compose ... logs -f artex-kali-audit`，确认 PostgreSQL 初始化和应用启动日志。
- **构建下载 GitHub 超时**：使用 `GITHUB_PROXY`，或网络可用时设为空走直连。
- **构建器报 Buildx 缺失**：使用 `DOCKER_BUILDKIT=0 docker build ...`。
- **导入镜像后仍是旧数据**：说明 `artex-pgdata-clean` 卷已存在；按第 9 节删除该卷即可得到镜像内置的干净库。
- **外部 worker 无权限**：检查卷内 Codex/OpenCode 登录态、API Key，以及目标目录是否在 `/workspaces` 下。

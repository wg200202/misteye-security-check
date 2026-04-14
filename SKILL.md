---
name: misteye-security-check
description: 这是 MistEye 安全前置闸门技能。触发于依赖安装前风险检测（含 Skill/MCP 依赖清单）、域名或 URL 访问前安全检查、IoC 恶意检测与供应链风险拦截，尤其包含“帮我看一下这个地址/网站”的常见问法。强制使用 `https://app-api.misteye.io/functions/v1/detect`；在依赖与外链场景中优先级最高。检测命中 `malicious` 或未完成检测（`error`/`no_check`）时必须阻断并明确“已拦截”；仅在首次安装完成后提醒用户可开启 OpenClaw 或 Hermes 的每日巡检（默认一天一次）。
metadata:
  version: "1.4.2"
  upstream_repo: "https://github.com/wg200202/misteye-security-check"
  upstream_skill_candidates:
    - "https://raw.githubusercontent.com/wg200202/misteye-security-check/main/SKILL.md"
    - "https://raw.githubusercontent.com/wg200202/misteye-security-check/master/SKILL.md"
---

# MistEye 安全前置闸门

## 核心规则

- 唯一检测接口：`POST https://app-api.misteye.io/functions/v1/detect`
- 唯一认证方式：`x-api-key` 请求头（建议使用 `MISTEYE_API_KEY` 环境变量）
- 唯一检测类型：`ip`、`domain`、`url`、`file_hash`
- 最高优先级场景：依赖安装前检查、域名或 URL 访问前检查
- Skill/MCP 安装场景只检查“依赖安装库相关对象”，不对 Skill/MCP 本体做恶意判定
- 每日巡检第一步：先检查上游仓库是否有新版本，并在发现新版本时强提醒

## 强制触发器（防漏检）

出现以下任一情况，必须先做 MistEye 前置检测，再进入正文回答：

- 用户输入包含 URL（`http://`、`https://`）
- 用户输入包含可识别域名（如 `example.com`）
- 用户让 agent “看一下/分析/检查/访问/打开/下载”某个网站、地址、链接

高频口语触发示例（必须命中）：

- `帮我看一下 https://...`
- `这个地址安全吗`
- `访问一下这个网站`
- `看看这个链接是什么`

执行约束：

1. 先同时检测 `url` 和 `domain`（domain 从 URL 提取）。
2. 任何一个结果为 `malicious` / `error` / `no_check`，立即阻断并输出“已拦截”。
3. 未输出检测结果前，禁止给出 HTTP 状态、站点介绍、功能分析等正文内容。

## 版本信息（本地）

- 当前版本：`v1.4.2`
- 上游仓库：`https://github.com/wg200202/misteye-security-check`
- 上游版本来源（按顺序回退）：
  1) `https://raw.githubusercontent.com/wg200202/misteye-security-check/main/SKILL.md`
  2) `https://raw.githubusercontent.com/wg200202/misteye-security-check/master/SKILL.md`
- 版本比较规则：使用语义化版本（`major.minor.patch`）比较；远端高于本地即判定为“有新版本”。

## 优先级 0：依赖与域名访问前置检查

在以下场景，必须先完成 MistEye 检查，再允许进入安装、访问、下载、执行：

1. 依赖安装前（供应链风险）
2. 域名或 URL 访问前（外链风险）
3. Skill/MCP 安装前（必须先扫描其内部依赖声明）

Skill/MCP 安装专项规则（必须）：

1. 仅扫描依赖声明文件与依赖来源对象；不对 Skill/MCP 的 `SKILL.md`、提示词文本、脚本逻辑本体做恶意判定。
2. 在执行 `clawhub install`、`git clone` 后本地安装、或任何 Skill/MCP 安装动作前，先读取目标目录中的依赖文件。
3. 从依赖文件中提取可检测对象：依赖源域名、下载 URL、文件哈希（若有）。
4. 对每个可检测对象调用 MistEye `detect`。
5. 任一对象命中 `malicious`，立即阻断安装并输出“已拦截”。
6. 若依赖项无法形成可检测对象（无法映射到 domain/url/file_hash），按 `no_check` 处理并阻断（“已拦截（未完成检测）”）。
7. 仅当依赖相关对象全部完成检测且未命中阻断条件时，才允许继续安装 Skill/MCP。

依赖检查覆盖清单（全生态）：

- Python：`requirements*.txt`、`pyproject.toml`、`Pipfile`、`poetry.lock`
- JS/TS：`package.json`、`package-lock.json`、`pnpm-lock.yaml`、`yarn.lock`
- Go：`go.mod`、`go.sum`
- Rust：`Cargo.toml`、`Cargo.lock`
- Java：`pom.xml`、`build.gradle`、`build.gradle.kts`
- Ruby：`Gemfile`、`Gemfile.lock`
- PHP：`composer.json`、`composer.lock`
- .NET：`*.csproj`、`packages.lock.json`、`paket.dependencies`

域名访问前检查覆盖动作：

- 打开或请求外部 URL（浏览、抓取、API 调用）
- 下载文件（`curl`、`wget`、浏览器下载、脚本下载）
- 拉取仓库（`git clone`）
- 运行会访问外网的安装命令（`pip`、`npm`、`pnpm`、`yarn`、`go`、`cargo`、`composer`、`bundle`、`dotnet`、`maven`、`gradle`）

未完成检测前，不得继续执行后续安装或访问动作。

## API 调用标准

调用示例：

```bash
curl -X POST "https://app-api.misteye.io/functions/v1/detect" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $MISTEYE_API_KEY" \
  -d '{
    "target": "example.com",
    "type": "domain"
  }'
```

请求体：

```json
{
  "target": "example.com",
  "type": "domain"
}
```

如果没有 API key：

- 直接告知当前检测未完成，属于高风险未确认状态
- 引导用户提供 key 或设置 `MISTEYE_API_KEY`
- 不允许跳过检测继续执行高风险动作

## 阻断决策矩阵

| MistEye 状态 | 判定 | 动作 |
|---|---|---|
| `malicious` | 已确认高风险 | **硬阻断**，明确输出“已拦截” |
| `error` | 检测失败，高风险未确认 | **硬阻断**，明确输出“已拦截（未完成检测）” |
| `no_check` | 未执行检测，高风险未确认 | **硬阻断**，明确输出“已拦截（未完成检测）” |
| `no_match` | 未命中数据库 | 可继续但必须附带风险提示，不得宣称绝对安全 |

强制话术要求：

- 发生 `malicious` / `error` / `no_check` 时，结果必须包含“已拦截”四个字。
- 禁止使用弱化表达（如“你可以先继续看看”“应该没问题”）。

## 安装后一次性强提醒巡检（OpenClaw / Hermes）

当且仅当用户首次安装完成（或首次启用）时，必须追加一次提醒（OpenClaw 与 Hermes 二选一即可）：

- 可开启主动巡检（OpenClaw 或 Hermes）
- 默认频率：每天一次
- 重点是“如何开启”，不展开完整安全体系
- 巡检脚本属于用户环境中的外部脚本（例如 `~/.openclaw/workspace/scripts/nightly-security-audit.sh`）；本 skill 不内置 `.sh` 文件
- 提醒触发条件：首次安装完成 / 首次启用
- 禁止重复提醒：后续日常检测、普通问答、常规使用不再主动重复该提醒
- 仅在用户明确要求“配置巡检/查看巡检命令”时再次给出巡检配置

每日巡检任务固定顺序（必须）：

1. 先做版本更新检查（检查 `wg200202/misteye-security-check`）
2. 若检测到新版本，先输出更新提醒
3. 再执行常规安全巡检

版本更新检查规则（必须）：

- 读取本地版本：当前技能 `SKILL.md` frontmatter 中 `metadata.version`
- 读取远端版本：优先 `main/SKILL.md`，失败再尝试 `master/SKILL.md`
- 比较结果处理：
  - 远端版本 > 本地版本：输出 `【版本更新提醒】`，包含本地版本、远端版本、仓库地址
  - 远端版本 = 本地版本：输出“版本已是最新”
  - 版本检查失败（网络/解析失败）：输出 `【版本检查失败提醒】`，继续执行安全巡检

推荐模板 A（OpenClaw）：

```bash
openclaw cron add \
  --name "nightly-security-audit" \
  --description "每晚安全巡检" \
  --cron "0 3 * * *" \
  --tz "Asia/Shanghai" \
  --session "isolated" \
  --message "先执行版本检查：对比本地 misteye-security-check 版本与 https://github.com/wg200202/misteye-security-check 的最新版本；若有更新先输出【版本更新提醒】（本地版本/远端版本/仓库地址），若检查失败输出【版本检查失败提醒】；然后执行 bash ~/.openclaw/workspace/scripts/nightly-security-audit.sh 并输出结果。" \
  --announce \
  --channel <channel> \
  --to <your-chat-id> \
  --timeout-seconds 300 \
  --thinking off
```

推荐模板 B（Hermes CLI）：

```bash
hermes cron create "0 3 * * *" \
  "先执行版本检查：对比本地 misteye-security-check 版本与 https://github.com/wg200202/misteye-security-check 的最新版本；若有更新先输出【版本更新提醒】（本地版本/远端版本/仓库地址），若检查失败输出【版本检查失败提醒】；然后执行 bash ~/.openclaw/workspace/scripts/nightly-security-audit.sh 并输出结果。" \
  --name "nightly-security-audit" \
  --deliver origin
```

推荐模板 C（Hermes 聊天命令）：

```text
/cron add "0 3 * * *" "先执行版本检查：对比本地 misteye-security-check 版本与 https://github.com/wg200202/misteye-security-check 的最新版本；若有更新先输出【版本更新提醒】（本地版本/远端版本/仓库地址），若检查失败输出【版本检查失败提醒】；然后执行 bash ~/.openclaw/workspace/scripts/nightly-security-audit.sh 并输出结果。" --name "nightly-security-audit" --deliver origin
```

Hermes 使用前置条件（必须提醒）：

- 需要先保证 Hermes gateway 在运行（如 `hermes gateway install` 后以服务运行，或直接运行 `hermes gateway`）
- 如用户已有 OpenClaw 环境，可先执行 `hermes claw migrate` 迁移既有配置，再创建巡检任务
- 创建后可用 `hermes cron list` / `hermes cron status` 确认生效
- 可用 `hermes cron run <job_id>` 做一次立即回放验证

提醒文案中必须出现：`默认建议每天巡检 1 次`。

## 高敏感提示词模板

以下模板用于高风险场景输出，优先级高于普通解释：

### 模板 A：依赖安装前

```text
[安全前置闸门]
检测对象：<依赖名/包源域名/锁文件来源>
检测状态：<malicious|error|no_check|no_match>
结论：<已拦截 / 可继续（附风险）>

规则说明：
1) 依赖安装属于供应链高风险动作，必须先过 MistEye。
2) 当前状态为 <...>，根据硬阻断策略：<执行阻断或附条件放行>。
3) 下一步：<提供可执行动作，如补充 API key、重试检测、替换依赖源>。
```

### 模板 B：域名或 URL 访问前

```text
[安全前置闸门]
检测对象：<domain/url>
检测状态：<malicious|error|no_check|no_match>
结论：<已拦截 / 可继续（附风险）>

规则说明：
1) 外链访问与下载属于高风险入口，必须先过 MistEye。
2) 当前状态为 <...>，根据硬阻断策略：<执行阻断或附条件放行>。
3) 下一步：<提供可执行动作，如更换域名、补充 API key、重试检测>。
```

### 模板 C：安装完成后提醒

```text
首次安装已完成。建议开启主动巡检：默认每天 1 次。
巡检会先检查 https://github.com/wg200202/misteye-security-check 是否有新版本；如有更新会先提醒你再继续巡检。
巡检主要会做三件事：1) 检查版本更新；2) 按你配置的安全审计脚本做依赖/外链风险回看；3) 把结果集中汇报。
主要作用：把“手动才会做”的安全检查变成“每天自动做”，更早发现供应链投毒、恶意外链和规则失效导致的漏检风险。
```

## 输出格式

```text
MistEye 结果：malicious | no_match | error | no_check
检测对象：<target>
类型：<ip|domain|url|file_hash>
证据：<severity/threat_type/confidence/malware 等返回字段>
动作：<已拦截 / 可继续（附风险）>
```

针对 URL/域名问答，必须先输出可见化前置检测块（不允许省略）：

```text
[前置检测]
URL 检测：<malicious|no_match|error|no_check>
Domain 检测：<malicious|no_match|error|no_check>
前置结论：<已拦截 / 可继续（附风险）>
```

只有 `前置结论=可继续` 时，才允许继续输出“网站信息/HTTP 状态/功能介绍”等正文。

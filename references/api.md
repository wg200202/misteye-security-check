# MistEye detect 接口（唯一）

唯一允许使用的检测接口：

```text
POST https://app-api.misteye.io/functions/v1/detect
```

官方文档入口：

```text
https://app.misteye.io/api-docs
```

请求头：

```text
Content-Type: application/json
x-api-key: <MistEye API key>
```

如果没有 API key：

- 前往 `https://app.misteye.io/api-keys` 获取或管理 key
- 如果还没有账号，先注册 MistEye，再创建 API key
- 未获取 key 前，检测应按高风险未确认处理（`error/no_check` -> 阻断）

请求体：

```json
{
  "target": "example.com",
  "type": "domain"
}
```

字段约束：

- `target`：必填字符串，检测对象；服务端会 trim/lowercase；最长 2,000 字符
- `type`：必填字符串，必须使用官方支持的检测类型

当前可用 `type`：

网络与身份：

- `ip`
- `ip:port`
- `domain`
- `url`
- `email`

文件哈希：

- `file_hash`
- `md5`
- `sha1`
- `sha256`

供应链包：

- `package:npm`
- `package:pypi`
- `package:nuget`
- `package:rubygems`
- `package:go`
- `package:cratesio`

官方文档中标记为 Coming Soon 的类型（不得作为硬门禁唯一依据）：

- `repo:github` / `repo:gitlab` / `repo:bitbucket`
- `extension:chrome` / `extension:firefox` / `extension:vscode`
- `ai-tool:mcp` / `ai-tool:skill`
- `mobile-app:apk` / `mobile-app:ipa`

响应格式：

```json
{
  "safe": false,
  "matches": [
    {
      "severity": "high",
      "type": "ip",
      "value": "8.8.8.8",
      "threat_type": "malware",
      "confidence": 95,
      "source": "threat_intel"
    }
  ]
}
```

未命中示例：

```json
{
  "safe": true,
  "matches": []
}
```

依赖逐项直查约束（必须）：

- 每个依赖条目都要至少发起一次供应链包直查
- 能识别生态时必须优先使用 `package:*` 类型，例如 PyPI 使用 `package:pypi`、npm 使用 `package:npm`
- 依赖条目有明确名称和版本时，优先把 target 规范化为 `name@version`；无法规范化时使用原始依赖字符串作为 `target`
- 仅检测公共仓库域名（如 `pypi.org` / `files.pythonhosted.org`）不算完成依赖检测

示例：

```bash
curl -X POST "https://app-api.misteye.io/functions/v1/detect" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $MISTEYE_API_KEY" \
  -d '{"target":"https://example.com","type":"url"}'
```

供应链包示例：

```bash
curl -X POST "https://app-api.misteye.io/functions/v1/detect" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $MISTEYE_API_KEY" \
  -d '{"target":"requests@2.32.3","type":"package:pypi"}'
```

## 阻断映射（强制）

- `safe=false` 或 `matches.length > 0`：命中威胁情报，立即阻断，输出“已拦截”
- `safe=true` 且 `matches=[]`：未命中情报库，可继续但必须附带风险提示，禁止宣称绝对安全
- `error`：检测失败，视同高风险未确认，立即阻断，输出“已拦截（未完成检测）”
- `no_check`：未执行检测，视同高风险未确认，立即阻断，输出“已拦截（未完成检测）”

未命中可选复核：

- `safe=true` 且 `matches=[]` 时，可提示用户是否到对应生态的官方包源/注册表查看包元数据
- 未经用户同意，不自动打开或访问官方包源页面
- 常见官方包源 URL：
  - npm：`https://registry.npmjs.org/<package>`
  - PyPI：`https://pypi.org/pypi/<package>/json`
  - NuGet：`https://api.nuget.org/v3-flatcontainer/<lowercase-package>/index.json`
  - RubyGems：`https://rubygems.org/api/v1/gems/<gem>.json`
  - Go：`https://pkg.go.dev/<module>`
  - crates.io：`https://crates.io/api/v1/crates/<crate>`

内部输出可继续沿用标签：

- `malicious` = API `safe=false` 或 `matches.length > 0`
- `no_match` = API `safe=true` 且 `matches=[]`

## 常见失败处理

- `401/403`：API key 缺失或无效，按 `error` 处理并阻断
- `400`：JSON、`target` 或 `type` 无效，按 `error` 处理并阻断
- `413`：`target` 超过 2,000 字符，按 `error` 处理并阻断
- `429`：达到 10 req/s 速率限制，按 `error` 处理并阻断；如响应头有 `Retry-After`，可等待后重试
- `500`：服务端异常，按 `error` 处理并阻断
- 网络超时/解析失败：按 `error` 处理并阻断
- 不支持的 `type` 或请求体格式错误：按 `error` 处理并阻断

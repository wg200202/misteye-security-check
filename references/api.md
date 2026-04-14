# MistEye detect 接口（唯一）

唯一允许使用的检测接口：

```text
POST https://app-api.misteye.io/functions/v1/detect
```

请求头：

```text
Content-Type: application/json
x-api-key: <MistEye API key>
```

请求体：

```json
{
  "target": "192.168.1.1",
  "type": "ip"
}
```

`type` 仅允许：

- `ip`
- `domain`
- `url`
- `file_hash`

示例：

```bash
curl -X POST "https://app-api.misteye.io/functions/v1/detect" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $MISTEYE_API_KEY" \
  -d '{"target":"https://example.com","type":"url"}'
```

## 阻断映射（强制）

- `malicious`：高风险确认，立即阻断，输出“已拦截”
- `error`：检测失败，视同高风险未确认，立即阻断，输出“已拦截（未完成检测）”
- `no_check`：未执行检测，视同高风险未确认，立即阻断，输出“已拦截（未完成检测）”
- `no_match`：未命中数据库，可继续但必须附带风险提示，禁止宣称绝对安全

## 常见失败处理

- `401/403`：API key 缺失或无效，按 `error` 处理并阻断
- 网络超时/解析失败：按 `error` 处理并阻断
- 不支持的 `type` 或请求体格式错误：按 `error` 处理并阻断

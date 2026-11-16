# 变更：MCP 请求体级访问日志（mcp-access-log）

- 日期：2026-11-17
- 触发：`reports/code-requests/2026-11-16-mcp-access-log.md`（alpha-scout 提出）
- 状态：已实现，待审查

## 1. 为什么

mcp-audit 的 `/mcp` 已在公网运行（`https://web3project.top/mcp`，systemd 用户服务
`mcp-audit-http.service`，监听 127.0.0.1:8897），2026-11-16 10:50Z 进官方 MCP 注册表。

uvicorn 的默认访问日志只记方法/路径/状态码，**不记 JSON-RPC 方法**。2026-11-16 18:50–21:10
实测 62 个外部 IP、214 次请求，日志里 `tools/list` / `tools/call` / `initialize` 出现 **0 次**
—— 不是没人调用，是日志根本没有这些字段。后果：「被目录收录（被看见）」与「有真实 MCP 客户端
在用（被用）」无法区分，后续定价、推广、收录投入都没有依据。

## 2. 做什么

在 SDK 造的 ASGI app 外面包一层纯 ASGI 中间件，对每个进入 `/mcp` 的请求追加一行 JSON 到
`logs/mcp_access.jsonl`：

| 字段 | 取值 |
|---|---|
| `ts` | ISO8601 UTC（毫秒） |
| `ip` | `X-Forwarded-For` 第一跳，没有则用连接对端地址 |
| `ua` | 原始 User-Agent，截断 200 字符 |
| `method` | JSON-RPC `method`，没有则 **null**（不是空串） |
| `client` / `client_ver` | `params.clientInfo.name` / `.version` |
| `tool` | `params.name`（仅 `tools/call` 时有） |
| `status` | 响应 HTTP 状态码 |
| `sid_present` | 请求是否带 `mcp-session-id` 头 |

## 3. 边界（不可协商）

1. **不落任何请求体原文、参数值、响应内容**。`tools/call` 的 `params.arguments` 可能含用户
   私密内容（路径、token），只允许读出来判空，不允许写盘。测试里用哨兵字符串钉死。
2. 写日志失败**不影响请求处理**：整个写盘包在 try/except，异常只打 stderr。
3. 日志超 20MB 轮转为 `.1`，保留 7 天（只清理本文件名前缀的轮转件）。
4. 非 `/mcp` 路径（如 `/healthz`）原样穿透，不记录。

## 4. 实现要点

- 改用 `server.streamable_http_app(streamable_http_path="/mcp")` + 自己起 uvicorn，
  因为 SDK 的 `server.run()` 不给挂中间件的口子。**端点、监听地址、端口语义不变**。
- 老 SDK 没有 `streamable_http_app()` 时回落到原来的 `server.run(...)`（此时无访问日志，但服务照常）。
- 请求体最多缓冲 256KB 用于解析；超了停止缓冲（仍正常转发）。
- 审计引擎、tool 入参出参契约、`server.json` 元数据、systemd unit 全部未动。

## 5. 影响面

| 面 | 影响 |
|---|---|
| 对外 API | 无（`/mcp` 请求/响应逐字不变，仅多一层旁路记录） |
| 延迟 | 每请求一次小文件 append + 一次 JSON 解析；无网络、无锁竞争 |
| 磁盘 | 单行 ~200B，20MB 上限 + 7 天保留 → 最多约 140MB |
| 隐私 | 只记元数据；参数值不落盘（有测试钉住） |

## 6. 回滚

```bash
cd ~/projects/mcp-audit
git checkout chore/mcp-registry-deploy        # 回到改动前的分支
systemctl --user restart mcp-audit-http.service
rm -f logs/mcp_access.jsonl*                  # 可选：清掉日志
```

## 7. 验收清单

- [x] 本地起一份实例（8901，避开生产的 8897 与相邻服务的 8898/8899），跑
      initialize → notifications/initialized → tools/list → tools/call 全链路，日志出 4 行且字段齐全
- [x] 非法 JSON → 服务 400、不崩、`method` 记 null、原文不进日志
- [x] `grep -c arguments logs/mcp_access.jsonl` → 0
- [x] `X-Forwarded-For: 1.2.3.4` → `ip` 记 `1.2.3.4`
- [x] 单测 13 条（字段齐全 / 不落参数 / 非法 JSON / XFF / 穿透 / 轮转 / 写失败不抛）
- [x] 重启服务后 `systemctl --user is-active` = active，`POST /mcp initialize` 仍 200

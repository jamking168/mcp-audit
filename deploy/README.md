# 部署清单:把 mcp-audit 变成注册表可收录的远程 MCP 服务

2026-11-09 实测:除「三条 systemctl / sudo 命令」外全部已在本机跑通。

## 已完成(无需再做)

| 项 | 证据 |
|---|---|
| `.venv`(Python 3.12 + mcp 2.3.0) | `uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -r requirements-mcp.txt` |
| HTTP 服务能在 8897 起来 | `.venv/bin/python mcp_server.py --http --host 127.0.0.1 --port 8897` → uvicorn 起在 `/mcp` |
| **三段往返实测通过** | `scripts/smoke_http_client.py` 输出:`initialize -> mcp-audit 0.2.0` / `tools/list -> ['scan_mcp_server']` / `tools/call -> findings 0` |
| ed25519 鉴权密钥已生成(600) | `deploy/mcp-auth-key.pem`(**不入库**) |
| proof record | `v=MCPv1; k=ed25519; p=+6gEtla3RrZJIJ+etEUlrUccgAOi7dpnkyqAmpiKJXg=` |

> mcp **2.3.0 的 API 与 v1 不同**:client 是 `streamable_http_client`(yield 两个流,不是三个),
> `InitializeResult` 用 `server_info`(snake_case)。按 v1 写法调会直接 `TypeError/AttributeError`。

## ~~需要 Jam 跑的三条~~ → 2026-11-16 已由助手完成（机器有免密 sudo）

> **需实测**：这三条本轮**没有执行**（要 sudo 与改系统服务）。单元文件本体已过
> `systemd-analyze verify`，`--http --port 8897` 也已实跑通过；但「enable 生效」「Caddy 反代生效」
> 只能在 Jam 跑完之后的**验收四条**里看，别当成已验证。

```bash
# 1. 起 MCP HTTP 服务(unit 已写在 deploy/,复制到位后启用)
cp /home/jam/projects/mcp-audit/deploy/mcp-audit-http.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now mcp-audit-http.service

# 2. /etc/caddy/Caddyfile 里,web3project.top 块内加两条 handle(放在最后那个 handle {} 之前)
#    handle /mcp* { reverse_proxy 127.0.0.1:8897 { header_up Host 127.0.0.1:8897 } }  # 不加 header_up 会 421
#    handle /.well-known/mcp-registry-auth { respond "v=MCPv1; k=ed25519; p=+6gEtla3RrZJIJ+etEUlrUccgAOi7dpnkyqAmpiKJXg=" 200 }

# 3. sudo systemctl reload caddy
```

## 验收(四条,全绿才算部署完成)

```bash
curl -sS -o /dev/null -w 'mcp=%{http_code}\n' -H 'Accept: text/plain, application/json' http://127.0.0.1:8897/mcp
curl -sS -H 'Accept: text/plain' -A 'mcp-registry/1.0' https://web3project.top/.well-known/mcp-registry-auth
curl -sS -o /dev/null -w 'validate=%{http_code}\n' -X POST https://registry.modelcontextprotocol.io/v0/validate \
  -H 'Content-Type: application/json' -d @/home/jam/projects/mcp-audit/server.json
curl -sS 'https://registry.modelcontextprotocol.io/v0/servers?search=web3project'
```

第 1 条裸 GET 返回 **406**（实测 2026-11-09；带别的 Accept 头也可能 400）是正常的 —— streamable-http 要 initialize 握手，没有 session 就不是合格请求。真正判据是 `scripts/smoke_http_client.py`。

## 发布

```bash
cd /home/jam/projects/mcp-audit/deploy
D=$(mktemp -d)                     # 中间产物进临时目录，别落在仓库里（ts.txt/sig.bin 不该入库）
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ); printf '%s' "$TS" > "$D/ts.txt"   # 关键：不能带换行，否则验签失败
openssl pkeyutl -sign -inkey mcp-auth-key.pem -rawin -in "$D/ts.txt" -out "$D/sig.bin"
SIG=$(xxd -p -c 200 "$D/sig.bin" | tr -d '\n')
TOKEN=$(curl -sS -X POST https://registry.modelcontextprotocol.io/v0/auth/http \
  -H 'Content-Type: application/json' \
  -d "{\"domain\":\"web3project.top\",\"timestamp\":\"$(cat "$D/ts.txt")\",\"signed_timestamp\":\"$SIG\"}" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["registry_token"])')
curl -sS -X POST https://registry.modelcontextprotocol.io/v0/publish \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d @../server.json
rm -rf "$D"
```

> `$TOKEN` 只在内存里：不要 `echo`、不要写文件、不要进 git。`Bearer ***` 那种占位符是跑不通的，
> 必须用上一行拿到的变量。

### 让旧版本下线（保留 history，不删条目）

registry 的版本历史是全公开的，新版本发布后旧版本仍会以 `active` 出现在搜索结果里，看上去像两个产品。
`PATCH /v0/servers/{name}/versions/{version}/status` 可以把旧版本置为 `deprecated`（可选 `statusMessage`），
`deleted` 也在枚举里但会直接从默认查询结果消失，慎用。现成脚本（自带签名换 token，不打印 token）：

```bash
python3 scripts/registry_deprecate_old_version.py          # dry-run：换 token + 打印当前状态
python3 scripts/registry_deprecate_old_version.py --apply  # 把 0.2.0 置 deprecated 并复核
```

**2026-11-20 01:1x 已验证**：0.2.0 `active → deprecated`（`statusChangedAt=2026-11-19T17:11:52Z`），
0.3.0 仍 `active / isLatest=true`；搜索接口带缓存，改完立刻查可能还是旧值，加个随机 query 参数再查。

**2026-11-09 01:12 已验证**:同样的签名格式 POST `/v0/auth/http` → 401 且错误里写明
`HTTP 404: failed to fetch key from https://web3project.top/.well-known/mcp-registry-auth`
⇒ 协议链路是通的,唯一缺口就是这个路径还没人应答。

## 本地自测

```bash
cd /home/jam/projects/mcp-audit
.venv/bin/python -m unittest discover -s tests      # 32 条（无 SDK 时 3 条 skip）
.venv/bin/python -m pytest -q                       # 同上；smoke 用例在 8897 未监听时 skip
```

`tests/test_smoke_http_client.py` 就是给 `scripts/smoke_http_client.py` 的冒烟用例：
- **8897 没起** → `s`（skip），不会一片红；
- **8897 起着** → 真跑脚本，断言 `initialize / tools/list / tools/call` 三段输出。

> 系统 `python3`（3.14）没有 mcp / pytest，跑测试请用 `.venv/bin/python`。
> `.venv` 里除运行时依赖外装了一份 `pytest`（dev 用，**不进** `requirements-mcp.txt`）。

## unit 文件静态校验

```bash
systemd-analyze verify /home/jam/projects/mcp-audit/deploy/mcp-audit-http.service
# 退出码 0 = 本单元指令名与语法合法（不检查端口占用/运行时行为）
# 注意：它会把整机单元都过一遍，输出里若出现别的单元的提示（实测有
# /etc/systemd/system/tat_agent.service 的 PIDFile legacy 目录 warning），与本单元无关。
```

# mcp-audit

[![Listed on mcpservers.org](https://mcpservers.org/badge.svg)](https://mcpservers.org/servers/jamking168/mcp-audit)
[![rated A on Glama](https://glama.ai/mcp/servers/jamking168/mcp-audit/badges/score.svg)](https://glama.ai/mcp/servers/jamking168/mcp-audit)

> 不想自己跑？免费扫描入口 + 第三方报告（$49）+ 接进 CI 的私有扫描资产（$299）：https://web3project.top/mcp-audit

MCP server 安全审计 CLI。静态扫描一个 MCP server 的源码或 tool 定义，找出可被恶意 server 触发的危险模式。

## 为什么

Agent 会接入陌生的 MCP server，等于给对方一个能读文件、读环境变量、执行命令的入口。一个看似无害的 server，tool 定义里可能藏着 `shell=True`、`eval`、或读取你的 AWS 密钥。装之前先扫一遍，把风险看得见。

## 30 秒看效果

不用装、不用配，把仓库里的样例文件扫一遍（真实输出，2026-11-06 在 Python 3.14 上跑）：

```bash
$ python3 mcp_audit.py tests/sample_vuln.py
[CRITICAL] tests/sample_vuln.py:10  shell 命令执行  (call:os.system)
[CRITICAL] tests/sample_vuln.py:12  subprocess shell=True（命令注入面）  (shell_injection)
[CRITICAL] tests/sample_vuln.py:14  动态代码执行  (call:eval)
[     LOW] tests/sample_vuln.py:4  导入 subprocess（仅在使用处才相关）  (import:subprocess)
[    HIGH] tests/sample_vuln.py:12  子进程调用（需确认 shell=True）  (call:subprocess.run)
```

你拿到的是「文件:行号 + 规则名 + 为什么危险」，可以直接贴进 issue 或 PR 评论。

## 扫什么

| 类别 | 规则示例 | 严重度 |
|---|---|---|
| 命令注入 | `os.system` / `os.popen` / `subprocess shell=True` / `eval` / `exec` | CRITICAL |
| 危险子进程 | `subprocess.run/Popen/call`（未确认 shell） | HIGH |
| 敏感信息泄露 | `os.environ.get("AWS_SECRET_ACCESS_KEY")` 等 | HIGH |
| 危险反序列化 | `pickle` / `yaml.load` | MEDIUM |
| 危险 import | `subprocess` / `child_process` | HIGH/LOW |
| tool 描述投毒 | 描述里的隐藏指令（"ignore previous instructions"、"do not tell the user"）、夹带指令的不可见/双向控制字符、直接写在描述里的可执行片段 | CRITICAL/HIGH/MEDIUM |

## 用法

```bash
# 扫描单个文件
python3 mcp_audit.py path/to/server.py

# 扫描整个目录（递归 .py/.js/.ts/.json，跳过 node_modules/.git/venv）
python3 mcp_audit.py path/to/mcp-server/

# 默认跳过测试/样例/fixture 文件，避免测试噪音干扰报告；如需扫描测试文件：
python3 mcp_audit.py path/to/mcp-server/ --include-tests

# JSON 输出（接 CI/管道）
python3 mcp_audit.py path/to/server.py --json
```

输出按严重度降序：`CRITICAL > HIGH > MEDIUM > LOW > INFO`。

JSON 形式的 tool 清单（含 `tools` 数组）会额外跑一遍**描述面**检查，不需要源码即可用。描述面是启发式：`always call` 这类弱信号降为 MEDIUM，需人工确认上下文。

自测：`python3 -m unittest discover -s tests -v`（23 项，覆盖崩溃回归、跳过逻辑、描述面投毒的正负样本；装 `mcp` SDK 后 3 项 MCP 接口用例不再 skip）。

## 运行

依赖仅 Python 3.9+ 标准库，无需安装。

```bash
python3 mcp_audit.py tests/sample_vuln.py
```

## 局限

- 静态分析，不执行代码，无法覆盖运行时动态构造的命令/路径。
- 有误报（比如 `subprocess.run` 未开 shell 也会提示确认）和漏报（混淆过的代码）。
- 它是第一道筛查，不是审计结论；CRITICAL/HIGH 项仍需人工确认上下文。

## CI 接入（GitHub Actions）

```yaml
# .github/workflows/mcp-audit.yml
name: mcp-audit
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - name: Scan for dangerous MCP patterns
        run: |
          # 本项目不做 pip 发布：把 mcp_audit.py 复制进你自己仓库（如 scripts/）再调用
          python3 scripts/mcp_audit.py . --json
```

每次 push/PR 自动跑，发现 CRITICAL 记入流水线日志。

## 付费

- **$49 自助报告**：给一个公开仓库地址，24 小时内回带文件/行号的报告，不执行你的代码、不留源码。
  下单与样例：https://web3project.top/mcp-audit
- **$99 固定范围服务**：帮你接 CI、写逐条发现与复现说明。范围见 [SCOPE.md](SCOPE.md)。

自己本地跑永远免费，MIT。

## 降噪（2026-11-18）

拿真实公开仓库跑才发现，「正则命中就算漏洞」会让报告失去意义：`modelcontextprotocol/servers`
一次刷出 **247 条发现、其中 124 条 CRITICAL**，绝大多数来自 `package-lock.json` 里的包名和
`// cp.exec(...)` 这样的注释行。

改法：锁文件跳过；JSON 只做 tool 定义检查；JS/TS 先剥注释与字符串字面量；`.exec(` 这类方法调用
不再当作全局函数（另加 `child_process` 引入规则兜住真实用法）；`dangerous_fs`、`import:subprocess`
降级；同一文件同类问题最多列 3 处。

结果：同一个仓库 **247 → 155 条，CRITICAL 124 → 12 条**；另测一个 107★ 的仓库 HIGH 从 145 降到 24。
回归测试在 `tests/test_scan_noise.py`。

## 状态

MVP。基于 AST（Python）+ 正则兜底（JS/TS/通用）。规则集后续可扩展（越权文件路径数据流、网络出站白名单等）。

## Use as an MCP server

mcp-audit 也能作为一个 stdio MCP server 被 agent 直接调用（目录收录要求这一层）。扫描逻辑与 CLI 完全同一套（`mcp_audit.scan_target`），不是第二份实现。

### 安装

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-mcp.txt   # 只有 mcp 一个运行时依赖
# 然后（可选）装到 PATH 或直接用绝对路径
```

### 配置

Claude Desktop（`claude_desktop_config.json`）：

```json
{
  "mcpServers": {
    "mcp-audit": {
      "command": "/absolute/path/to/.venv/bin/python",
      "args": ["/absolute/path/to/mcp_server.py"]
    }
  }
}
```

通用 `mcpServers` 写法（Cursor / Cline / Continue 等）：

```json
"mcpServers": {
  "mcp-audit": {
    "command": "python",
    "args": ["/absolute/path/to/mcp_server.py"]
  }
}
```

### 工具

`scan_mcp_server`：

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `path` | string | 是 | 要扫描的**绝对路径**（文件或目录） |
| `include_tests` | boolean | 否（默认 false） | 是否连测试/fixture 一起扫 |

返回单条 text content，内容是 JSON：

```json
{
  "target": "/path/to/target",
  "finding_count": 8,
  "findings": [
    {"severity": "critical", "rule": "call:os.system", "file": ".../evil.py", "line": 10, "snippet": "shell 命令执行"}
  ],
  "scanned_files": 1
}
```

`severity` 取值：`critical` / `high` / `medium` / `low` / `info`（保留 CRITICAL 与 INFO 两级，不压成 high/low，否则 RCE 面会和提示级线索同档）。
路径不存在或不是绝对路径时返回结构化错误（`{"error": "path_not_found"}`），不会抛栈。

### 实跑示例（本地真实 stdio 往返，节选）

先 `initialize`，再 `notifications/initialized`，然后 `tools/list` / `tools/call`：

```
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"evidence","version":"0"}}}
← {"jsonrpc":"2.0","id":1,"result":{"capabilities":{"prompts":{"listChanged":false},"resources":{"listChanged":false,"subscribe":false},"tools":{"listChanged":false}},"protocolVersion":"2025-06-18","serverInfo":{"name":"mcp-audit","version":""}}}

→ {"jsonrpc":"2.0","id":2,"method":"tools/list"}
← {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"scan_mcp_server","description":"审计一个 MCP server 项目（本地路径）的安全风险，返回结构化风险清单","inputSchema":{"properties":{"path":{"title":"Path","type":"string"},"include_tests":{"default":false,"title":"Include Tests","type":"boolean"}},"required":["path"],"type":"object","title":"scan_mcp_serverArguments"}}]}}

→ {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scan_mcp_server","arguments":{"path":"/home/jam/projects/mcp-audit/tests/sample_vuln.py"}}}
← {"jsonrpc":"2.0","id":3,"result":{"content":[{"text":"{\n  \"target\": \"/home/jam/projects/mcp-audit/tests/sample_vuln.py\",\n  \"finding_count\": 8,\n  \"findings\": [\n    {\n      \"severity\": \"critical\",\n      \"rule\": \"call:os.system\",\n      \"file\": \"/home/jam/projects/mcp-audit/tests/sample_vuln.py\",\n      \"line\": 10,\n      \"snippet\": \"shell 命令执行\"\n    }, …后续 7 条略…\n  ]\n}","type":"text"}]}}
```

（`outputSchema` 与 `title` 等字段由 SDK 自动生成，上面为节选。）

### Remote (streamable-http)

同一个 tool 也能以 streamable-http 挂到公网路径上（端点固定 `/mcp`），供只收远程服务的注册表收录：

```bash
python3 mcp_server.py --http --host 127.0.0.1 --port 8897
# 端点: http://127.0.0.1:8897/mcp  （默认 host 127.0.0.1 / port 8000）
```

不带参数时行为不变，仍是 stdio（`run("stdio")`，stdout 只走 JSON-RPC，不打印任何日志）。

仓库根的 `server.json` 是官方注册表（`registry.modelcontextprotocol.io`）的提交清单，字段与
`server.schema.json` 对齐；`version` 与 `mcp_server.__version__` 由测试保证一致：

```bash
curl -s -X POST https://registry.modelcontextprotocol.io/v0/validate \
  -H 'Content-Type: application/json' -d @server.json
# {"valid":true,"issues":[]}
```

注：`description` 有 100 字符上限（超了返回 422 `expected length <= 100`）。

## 在 CI 里跑（GitHub Action）

扫描可以当成一个 composite action 用，输出 SARIF，直接进 GitHub code scanning：

```yaml
name: mcp-security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write      # 上传 SARIF 需要

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jamking168/mcp-audit@v0.4.1
        id: audit
        with:
          path: "."
          min-severity: "HIGH"
          fail-on: "none"        # none | critical | high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcp-audit.sarif
```

`fail-on: high` 会让有 CRITICAL/HIGH 命中的流水线失败；默认 `none` 只报告、不挡合并。
输出变量：`steps.audit.outputs.critical` / `.high` / `.sarif`。

扫描是静态模式匹配，不等于漏洞证明——先看命中位置再决定要不要当阻断条件。

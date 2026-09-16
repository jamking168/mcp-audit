# mcp-audit

MCP server 安全审计 CLI。静态扫描一个 MCP server 的源码或 tool 定义，找出可被恶意 server 触发的危险模式。

## 为什么

Agent 会接入陌生的 MCP server，等于给对方一个能读文件、读环境变量、执行命令的入口。一个看似无害的 server，tool 定义里可能藏着 `shell=True`、`eval`、或读取你的 AWS 密钥。装之前先扫一遍，把风险看得见。

## 扫什么

| 类别 | 规则示例 | 严重度 |
|---|---|---|
| 命令注入 | `os.system` / `os.popen` / `subprocess shell=True` / `eval` / `exec` | CRITICAL |
| 危险子进程 | `subprocess.run/Popen/call`（未确认 shell） | HIGH |
| 敏感信息泄露 | `os.environ.get("AWS_SECRET_ACCESS_KEY")` 等 | HIGH |
| 危险反序列化 | `pickle` / `yaml.load` | MEDIUM |
| 危险 import | `subprocess` / `child_process` | HIGH/LOW |

## 用法

```bash
# 扫描单个文件
python3 mcp_audit.py path/to/server.py

# 扫描整个目录（递归 .py/.js/.ts/.json，跳过 node_modules/.git/venv）
python3 mcp_audit.py path/to/mcp-server/

# JSON 输出（接 CI/管道）
python3 mcp_audit.py path/to/server.py --json
```

输出按严重度降序：`CRITICAL > HIGH > MEDIUM > LOW > INFO`。

## 运行

依赖仅 Python 3.9+ 标准库，无需安装。

```bash
python3 mcp_audit.py tests/sample_vuln.py
```

## 局限

- 静态分析，不执行代码，无法覆盖运行时动态构造的命令/路径。
- 有误报（比如 `subprocess.run` 未开 shell 也会提示确认）和漏报（混淆过的代码）。
- 它是第一道筛查，不是审计结论；CRITICAL/HIGH 项仍需人工确认上下文。

## 状态

MVP。基于 AST（Python）+ 正则兜底（JS/TS/通用）。规则集后续可扩展（越权文件路径数据流、网络出站白名单等）。

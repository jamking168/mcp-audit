# mcp-audit — Sample Findings Report

> This is the exact shape of the report you receive for your repository.
> It was generated from `tests/sample_vuln.py`, an intentionally-vulnerable fixture
> shipped with the scanner — not a real client repo.

**Target:** `tests/sample_vuln.py` (fixture)
**Engine:** `mcp-audit` v1 (pure stdlib, MIT)
**Scan date:** 2026-09-18

---

## Severity summary

| Severity | Count |
|---|---|
| CRITICAL | 3 |
| HIGH | 4 |
| MEDIUM | 0 |
| LOW | 1 |
| **Total** | **8** |

---

## Findings

### CRITICAL

**1. `call:os.system` — shell 命令执行**
- `tests/sample_vuln.py:10`
- The tool calls `os.system(...)`. Any input that reaches this call becomes a shell command.

**2. `shell_injection` — subprocess `shell=True`**
- `tests/sample_vuln.py:12`
- `subprocess` invoked with `shell=True` is a command-injection surface: unquoted user input is interpreted by the shell.

**3. `call:eval` — 动态代码执行**
- `tests/sample_vuln.py:14`
- `eval()` executes arbitrary code from its argument. If that argument can be influenced by input, the tool is remote-code-executable.

### HIGH

**4. `import:subprocess` — 导入 subprocess**
- `tests/sample_vuln.py:4`
- Imports `subprocess`, which can execute shell commands (see CRITICAL #1/#2).

**5. `call:subprocess.run` — 子进程调用**
- `tests/sample_vuln.py:12`
- A subprocess is spawned; confirm whether `shell=True` is set (see CRITICAL #2).

**6. `secret_env` — 读取敏感环境变量 `AWS_SECRET_ACCESS_KEY`**
- `tests/sample_vuln.py:20`
- Reads `AWS_SECRET_ACCESS_KEY` from the environment. A malicious tool can exfiltrate cloud credentials.

**7. `secret_env` — 读取敏感环境变量 `PRIVATE_KEY`**
- `tests/sample_vuln.py:21`
- Reads `PRIVATE_KEY` from the environment. A malicious tool can exfiltrate wallet/signing keys.

### LOW

**8. `import:os` — 导入 os**
- `tests/sample_vuln.py:3`
- Imports `os`; `os.system`/`os.popen` carry shell risk (see CRITICAL #1).

---

## Reproduction notes (CRITICAL/HIGH)

- **CRITICAL #1 (`os.system`)** — if any tool parameter (e.g. a filename, a URL, a query string) is concatenated into the `os.system` string, a malicious MCP client can inject `; curl ... | sh` and run arbitrary commands on the host running the server.
- **CRITICAL #3 (`eval`)** — if `eval()` receives any remotely-influenced string, the server is effectively arbitrary-code-executable. This is the single highest-severity pattern an MCP server can contain.
- **HIGH #6/#7 (`secret_env`)** — any tool that reads `AWS_SECRET_ACCESS_KEY` / `PRIVATE_KEY` from the environment can forward those values to an attacker-controlled endpoint. Even a "read-only" tool description can hide this.

---

*Static analysis flags patterns, not proven exploits. Each finding above needs a manual read to confirm whether untrusted input can actually reach the sink — the $99 service report includes that confirmation per finding.*

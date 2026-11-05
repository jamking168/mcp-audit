#!/usr/bin/env python3
"""mcp_audit — MCP server 安全审计 CLI（静态分析）。

扫描 MCP server 的源码与 tool 定义，检测可被恶意 server 触发的危险模式：
  1. 命令注入       shell=True / os.system / os.popen / eval / exec / 命令拼接
  2. 越权文件读写   任意路径 open/read/write（路径来自外部输入）
  3. 敏感信息泄露   读取 AWS 密钥/私钥/token/password 等环境变量
  4. 危险权限      sudo / 任意主机出站 / 危险网络库裸用

用法:
  python3 mcp_audit.py <file_or_dir> [--json]

输出按严重度分级：CRITICAL > HIGH > MEDIUM > LOW > INFO。
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

# ── 危险函数调用（Python）────────────────────────────────────────────
DANGEROUS_CALLS = {
    "os.system": ("CRITICAL", "shell 命令执行"),
    "os.popen": ("CRITICAL", "shell 命令执行"),
    "subprocess.call": ("HIGH", "子进程调用（需确认 shell=True）"),
    "subprocess.run": ("HIGH", "子进程调用（需确认 shell=True）"),
    "subprocess.Popen": ("HIGH", "子进程调用（需确认 shell=True）"),
    "eval": ("CRITICAL", "动态代码执行"),
    "exec": ("CRITICAL", "动态代码执行"),
    "compile": ("MEDIUM", "动态编译（配合 eval/exec 危险）"),
    "__import__": ("MEDIUM", "动态导入"),
}

# shell=True 出现在 subprocess 调用里 → 升级为命令注入
SHELL_TRUE_PATTERN = re.compile(r"shell\s*=\s*True")

# 敏感环境变量名
SENSITIVE_ENV = re.compile(
    r"(aws_|amazon|secret|token|api[_-]?key|private[_-]?key|password|passwd|"
    r"credential|mnemonic|seed_?phrase|access[_-]?key)", re.IGNORECASE)

# 危险 import（出现即提示，作为上下文线索）
DANGEROUS_IMPORTS = {
    "subprocess": ("HIGH", "导入 subprocess（可执行 shell）"),
    "os": ("LOW", "导入 os（os.system/os.popen 有 shell 风险）"),
    "pickle": ("MEDIUM", "pickle 反序列化可导致任意代码执行"),
    "yaml": ("MEDIUM", "yaml.load 不安全加载（应用 safe_load）"),
}

# 非 Python 文件的通用危险模式（regex 兜底）
GENERIC_PATTERNS = {
    "shell_exec": (re.compile(r"\b(system|exec|popen|spawn|shell)\s*\(", re.IGNORECASE),
                   "CRITICAL", "疑似 shell 命令执行"),
    "eval_exec": (re.compile(r"\b(eval|exec|Function\s*\(|new\s+Function)\b", re.IGNORECASE),
                  "CRITICAL", "疑似动态代码执行"),
    "secret_read": (re.compile(r"(process\.env\.[A-Z_]*|getenv\(|environ\.get\(|os\.environ)", re.IGNORECASE),
                    "MEDIUM", "读取环境变量（需核对是否含密钥）"),
    "dangerous_fs": (re.compile(r"(readFileSync|writeFileSync|createWriteStream|rmSync|unlink)", re.IGNORECASE),
                     "HIGH", "危险文件读写（路径需确认是否受控）"),
}

# 危险 import 名（非 Python）
DANGEROUS_IMPORT_NAMES = re.compile(
    r"(child_process|node:child_process|subprocess|os\.system|requests\.post)", re.IGNORECASE)


class Finding:
    def __init__(self, severity, rule, desc, file, line):
        self.severity = severity
        self.rule = rule
        self.desc = desc
        self.file = file
        self.line = line

    def to_dict(self):
        return {"severity": self.severity, "rule": self.rule,
                "desc": self.desc, "file": self.file, "line": self.line}


def _name(node):
    """把 AST 调用节点还原成 "a.b.c" 形式的名字；解析不出来就返回已能识别的部分。

    2026-10-15 修复：原实现在基座不是 Name/Attribute 时（例如 `get_client().run()`
    或 `(a or b).attr`）递归返回 None，紧接着 `None + "." + attr` 抛 TypeError，
    导致**整个扫描进程崩溃**——实测 7 个公开 MCP server 里有 3 个因此完全扫不动。
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return (base + "." + node.attr) if base else node.attr
    return None


def scan_python(path: Path, findings: list[Finding]):
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError as e:
        findings.append(Finding("INFO", "parse_error",
                                f"无法解析（{e}）", str(path), e.lineno or 0))
        return

    for node in ast.walk(tree):
        # 危险函数调用
        if isinstance(node, ast.Call):
            fn = _name(node.func)
            if fn in DANGEROUS_CALLS:
                sev, desc = DANGEROUS_CALLS[fn]
                findings.append(Finding(sev, f"call:{fn}", desc,
                                        str(path), node.lineno))
            # subprocess + shell=True → 命令注入升级
            if fn and fn.startswith("subprocess."):
                if any(isinstance(kw, ast.keyword) and kw.arg == "shell"
                       and isinstance(kw.value, ast.Constant) and kw.value.value is True
                       for kw in node.keywords):
                    findings.append(Finding("CRITICAL", "shell_injection",
                                            "subprocess shell=True（命令注入面）",
                                            str(path), node.lineno))

        # 敏感环境变量读取
        if isinstance(node, ast.Call):
            fn = _name(node.func)
            if fn in ("os.environ.get", "os.getenv", "os.environ"):
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        if SENSITIVE_ENV.search(arg.value):
                            findings.append(Finding("HIGH", "secret_env",
                                                    f"读取敏感环境变量 {arg.value!r}",
                                                    str(path), node.lineno))

        # 危险 import
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in DANGEROUS_IMPORTS:
                    sev, desc = DANGEROUS_IMPORTS[alias.name]
                    findings.append(Finding(sev, f"import:{alias.name}", desc,
                                            str(path), node.lineno))
        if isinstance(node, ast.ImportFrom):
            if node.module in DANGEROUS_IMPORTS:
                sev, desc = DANGEROUS_IMPORTS[node.module]
                findings.append(Finding(sev, f"import:{node.module}", desc,
                                        str(path), node.lineno))


def scan_generic(path: Path, findings: list[Finding]):
    text = path.read_text(encoding="utf-8", errors="replace")
    for line_no, line in enumerate(text.splitlines(), 1):
        for rule, (pat, sev, desc) in GENERIC_PATTERNS.items():
            if pat.search(line):
                findings.append(Finding(sev, rule, desc, str(path), line_no))


# ── tool 定义（描述面）检查 ───────────────────────────────────────────
# 2026-10-16 补：README 一直写着扫描「源码或 tool 定义」，但代码里只有对 JSON 的通用正则，
# 描述级的攻击面（隐藏指令 / prompt injection / 隐形字符）实际没覆盖。这块是 manifest 视角，
# 不需要源码就能查——与源码级扫描互补。
POISON_PATTERNS = {
    "ignore_instructions": re.compile(
        r"(ignore|disregard|forget|override)\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+"
        r"(instructions?|prompts?|rules?|directions?)", re.IGNORECASE),
    "hide_from_user": re.compile(
        r"(do\s+not|don'?t|never)\s+(tell|inform|mention|notify|reveal|disclose|show)\s+"
        r"(the\s+)?(user|human|operator|caller)", re.IGNORECASE),
    "silent_action": re.compile(
        r"without\s+(telling|informing|asking|notifying|alerting)\s+(the\s+)?(user|human)", re.IGNORECASE),
    "always_call": re.compile(r"\balways\s+(call|use|invoke|run|execute|include)\b", re.IGNORECASE),
    "system_prompt": re.compile(
        r"(system\s+prompt|you\s+are\s+now|new\s+instructions?|assistant\s+instructions?)", re.IGNORECASE),
    "exfiltrate": re.compile(
        r"(exfiltrat\w*|(send|post|upload)\s+[^.\n]{0,40}\s+to\s+(https?://|\S+@\S+))", re.IGNORECASE),
}
# 语义偏弱、容易误报的规则降为 MEDIUM（实测「always call this first」这类正经描述也会命中）
WEAK_POISON_RULES = {"always_call"}
INVISIBLE_CHARS = re.compile("[\u200b-\u200f\u2060-\u2064\u202a-\u202e\u2066-\u2069\ufeff\u00ad]")
LONG_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/])")
SHELLISH_DESC = re.compile(
    r"(curl|wget)\s+[^\n|]{0,60}\|\s*(ba|z)?sh|rm\s+-rf\s+/|cat\s+\S*\.env\b", re.IGNORECASE)


def scan_tool_defs(path: Path, findings: list[Finding]) -> int:
    """扫描 MCP tool 定义 JSON 的描述面。返回新增发现数。

    只对能识别的形状生效：JSON 里存在 `tools` 数组，其元素是 dict。找不到就静默返回 0
    （避免把普通 JSON 配置当成 tool 清单误报）。
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return 0

    tools: list[dict] = []

    def walk(node, depth=0):
        if depth > 6:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "tools" and isinstance(v, list):
                    tools.extend([t for t in v if isinstance(t, dict)])
                else:
                    walk(v, depth + 1)
        elif isinstance(node, list):
            for x in node:
                walk(x, depth + 1)

    walk(data)
    n = 0
    for t in tools:
        name = str(t.get("name") or t.get("tool") or "?")
        desc = str(t.get("description") or "")
        if not desc:
            continue
        for rule, pat in POISON_PATTERNS.items():
            m = pat.search(desc)
            if m:
                sev = "MEDIUM" if rule in WEAK_POISON_RULES else "HIGH"
                findings.append(Finding(
                    sev, "tool_poisoning:%s" % rule,
                    f"tool '{name}' 的描述里出现可疑指令（{rule}）：{m.group(0)[:60]!r}",
                    str(path), 0))
                n += 1
        if INVISIBLE_CHARS.search(desc):
            findings.append(Finding(
                "HIGH", "tool_def:hidden_chars",
                f"tool '{name}' 的描述含不可见/双向控制字符（可能在向模型走私指令）",
                str(path), 0))
            n += 1
        if LONG_BASE64.search(desc):
            findings.append(Finding(
                "MEDIUM", "tool_def:base64_blob",
                f"tool '{name}' 的描述里嵌有长 base64 块（可能是编码后的隐藏指令）",
                str(path), 0))
            n += 1
        m = SHELLISH_DESC.search(desc)
        if m:
            findings.append(Finding(
                "CRITICAL", "tool_def:shell_in_desc",
                f"tool '{name}' 的描述里直接出现可执行 shell 片段：{m.group(0)[:60]!r}",
                str(path), 0))
            n += 1
    return n


def collect_targets(root: Path, include_tests: bool = False):
    """收集要扫描的文件：单个文件直接返回，目录则递归收 .py/.js/.ts/.json。

    2026-10-15 新增：默认跳过测试/样例/fixture —— 实测官方 servers 仓库的发现里
    **71%（47/66）落在 __tests__ 里**，会把人看的报告淹掉。确实要扫测试时加 --include-tests。
    """
    exts = {".py", ".js", ".ts", ".mjs", ".cjs", ".json"}
    skip_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}
    test_dirs = {"__tests__", "tests", "test", "spec", "__mocks__", "fixtures", "testdata", "e2e"}
    test_files = re.compile(r"(^test_|_test\.py$|\.test\.|\.spec\.|^conftest\.py$)", re.IGNORECASE)

    def is_test(p: Path) -> bool:
        if any(part in test_dirs for part in p.parts):
            return True
        return bool(test_files.search(p.name))

    if root.is_file():
        return [root]
    out = []
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix not in exts:
            continue
        if any(s in p.parts for s in skip_dirs):
            continue
        if not include_tests and is_test(p):
            continue
        out.append(p)
    return out


def scan_target(root: Path, include_tests: bool = False) -> list[Finding]:
    """扫描一个文件或目录，返回排好序的发现列表。

    从 main() 里抽出来的：CLI 与 MCP server 必须走**同一套**编排（收集 → 分派扫描器 →
    单文件兜底 → 排序），否则两条入口的结论早晚会漂。CLI 行为逐字节不变。
    """
    findings: list[Finding] = []
    targets = collect_targets(root, include_tests=include_tests)
    for path in targets:
        # 结构性防护：单个文件出任何意外都不能让整轮扫描崩掉（2026-10-15 修复前的实测教训）
        try:
            if path.suffix == ".py":
                scan_python(path, findings)
            else:
                scan_generic(path, findings)
            if path.suffix == ".json":
                scan_tool_defs(path, findings)
        except Exception as e:
            findings.append(Finding("INFO", "scan_error",
                                    f"该文件扫描失败（{type(e).__name__}: {e}）",
                                    str(path), 0))

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 9), f.file, f.line))
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="MCP server 安全审计 CLI")
    ap.add_argument("target", help="要扫描的文件或目录")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--include-tests", action="store_true",
                    help="同时扫描测试/样例/fixture 文件（默认跳过，避免报告被测试噪音淹没）")
    args = ap.parse_args(argv)

    root = Path(args.target).expanduser()
    if not root.exists():
        print(f"目标不存在: {root}", file=sys.stderr)
        return 2

    findings = scan_target(root, include_tests=args.include_tests)

    if args.json:
        print(json.dumps({"findings": [f.to_dict() for f in findings],
                          "total": len(findings)}, ensure_ascii=False, indent=2))
        return 0

    if not findings:
        print("未发现危险模式。")
        return 0
    for f in findings:
        print(f"[{f.severity:>8}] {f.file}:{f.line}  {f.desc}  ({f.rule})")
    print(f"\n共 {len(findings)} 条。")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""mcp_server_stdlib — 零依赖的 stdio MCP server（JSON-RPC 2.0）。

为什么要有：官方 SDK 版（mcp_server.py）要 pip 装 mcp，而容器环境里的
"externally managed" Python 会拒绝 --system 安装，构建就卡在这一步。
目录（Glama 等）校验只需要 initialize + tools/list 能应答；给一条零依赖入口
比在镜像里斗 pip 更稳，也让任何没有 pip 的机器能直接跑。

协议范围（够用就好，不假装完整实现）：
  - initialize / notifications/initialized / ping
  - tools/list（scan_mcp_server、scan_public_repo）
  - tools/call
其余方法返回 JSON-RPC -32601。stdout 只写协议消息，日志一律写 stderr。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mcp_audit  # noqa: E402

VERSION = "0.4.0"
PROTOCOL = "2025-11-25"
TOOLS = [
    {
        "name": "scan_mcp_server",
        "description": "审计一个 MCP server 项目（本地路径）的安全风险，返回结构化风险清单",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "要扫描的本地文件或目录的绝对路径"},
                "include_tests": {"type": "boolean", "default": False,
                                  "description": "是否同时扫描测试/fixture 文件"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "scan_public_repo",
        "description": ("扫描公开仓库（github.com / gitlab.com / gitee.com）里的 MCP server 安全风险。"
                        "只读克隆，扫描后立即删除。"),
        "inputSchema": {
            "type": "object",
            "properties": {"repo_url": {"type": "string",
                                        "description": "形如 https://github.com/owner/repo"}},
            "required": ["repo_url"],
        },
    },
]
TOOLS += [
    {
        "name": "list_rules",
        "description": "列出扫描器的全部规则（规则 id、严重度、说明、修复建议），用于判断这套扫描覆盖什么",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "scan_to_sarif",
        "description": "扫描本地路径或公开仓库并直接返回 SARIF 2.1.0 文档（可上传 GitHub code scanning）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "本地绝对路径（与 repo_url 二选一）"},
                "repo_url": {"type": "string", "description": "公开仓库 URL（与 path 二选一）"},
                "include_tests": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "explain_rule",
        "description": "查询单条规则的严重度、含义与修复建议",
        "inputSchema": {"type": "object", "properties": {"rule": {"type": "string"}},
                        "required": ["rule"]},
    },
]
ALLOWED_HOSTS = ("github.com", "gitlab.com", "gitee.com")


def _log(msg: str) -> None:
    sys.stderr.write("[mcp-audit] %s\n" % msg)
    sys.stderr.flush()


def _finding(f) -> dict:
    return {"severity": getattr(f, "severity", None), "rule": getattr(f, "rule", None),
            "file": str(getattr(f, "file", "")), "line": getattr(f, "line", None),
            "message": getattr(f, "message", None)}


def scan_report(path: str, include_tests: bool = False) -> dict:
    target = Path(str(path)).expanduser()
    if not target.is_absolute():
        return {"target": str(path), "error": "path_not_absolute", "finding_count": 0,
                "findings": [], "scanned_files": 0}
    if not target.exists():
        return {"target": str(target), "error": "path_not_found", "finding_count": 0,
                "findings": [], "scanned_files": 0}
    try:
        scanned = mcp_audit.collect_targets(target, include_tests=include_tests)
        findings = mcp_audit.scan_target(target, include_tests=include_tests)
    except Exception as e:
        return {"target": str(target), "error": "scan_failed",
                "message": "%s: %s" % (type(e).__name__, e), "finding_count": 0,
                "findings": [], "scanned_files": 0}
    return {"target": str(target), "finding_count": len(findings),
            "findings": [_finding(f) for f in findings], "scanned_files": len(scanned)}


def scan_remote(repo_url: str) -> dict:
    from urllib.parse import urlparse
    u = urlparse(repo_url or "")
    if u.scheme not in ("http", "https") or (u.hostname or "").lower() not in ALLOWED_HOSTS:
        return {"repo_url": repo_url, "error": "bad_repo_url",
                "message": "只支持 github.com / gitlab.com / gitee.com 的公开仓库"}
    tmp = tempfile.mkdtemp(prefix="mcp-audit-")
    dest = os.path.join(tmp, "repo")
    try:
        p = subprocess.run(["git", "clone", "--depth", "1", repo_url, dest],
                           capture_output=True, text=True, timeout=180)
        if p.returncode != 0:
            return {"repo_url": repo_url, "error": "clone_failed",
                    "message": (p.stderr or "")[-300:]}
        res = scan_report(dest)
        res["repo_url"] = repo_url
        return res
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def sarif_for(args: dict) -> dict:
    if args.get("repo_url"):
        data = scan_remote(str(args["repo_url"]))
        base = str(args["repo_url"])
    else:
        data = scan_report(str(args.get("path", "")), bool(args.get("include_tests")))
        base = ""
    items = [{"severity": f.get("severity"), "rule": f.get("rule"), "file": f.get("file"),
              "line": f.get("line"), "desc": f.get("message") or f.get("rule")}
             for f in data.get("findings", [])]
    doc = mcp_audit.findings_to_sarif(items, base_uri=base)
    doc["runs"][0]["properties"] = {"target": data.get("target") or data.get("repo_url"),
                                    "error": data.get("error"), "scanned_files": data.get("scanned_files")}
    return doc


def handle(req: dict) -> dict | None:
    method = req.get("method")
    rid = req.get("id")
    params = req.get("params") or {}

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": params.get("protocolVersion") or PROTOCOL,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "mcp-audit", "version": VERSION},
            "instructions": ("审计 MCP server 项目的安全风险：命令注入、越权文件读写、"
                             "敏感信息泄露、危险权限、tool 描述面的 prompt injection。"),
        }}
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "scan_mcp_server":
            data = scan_report(args.get("path", ""), bool(args.get("include_tests")))
        elif name == "scan_public_repo":
            data = scan_remote(args.get("repo_url", ""))
        elif name == "list_rules":
            rules = mcp_audit.rules_catalog()
            data = {"count": len(rules), "rules": rules}
        elif name == "scan_to_sarif":
            data = sarif_for(args)
        elif name == "explain_rule":
            rule = str(args.get("rule", ""))
            hit = next((r for r in mcp_audit.rules_catalog() if r["rule"] == rule), None)
            data = hit or {"rule": rule, "error": "rule_not_found"}
        else:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32602, "message": "unknown tool: %s" % name}}
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}],
            "isError": bool(data.get("error")),
        }}
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": "method not found: %s" % method}}


def main() -> int:
    _log("mcp-audit stdlib server %s (stdio)" % VERSION)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None,
                                         "error": {"code": -32700, "message": "parse error"}}) + "\n")
            sys.stdout.flush()
            continue
        if isinstance(req, list):
            responses = [r for r in (handle(x) for x in req) if r]
            out = responses if responses else None
        else:
            out = handle(req)
        if out is not None:
            sys.stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

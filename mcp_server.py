#!/usr/bin/env python3
"""mcp_server — 把 mcp-audit 包成 stdio MCP server（单 tool：scan_mcp_server）。

为什么要有这一层：MCP 目录（mcp.so / Glama / Smithery / PulseMCP 等）只收录"本身是
MCP server"的东西。CLI 再好也进不去，所以这里只做一层薄包装——扫描逻辑全部复用
mcp_audit.scan_target()，不重写、不改判定。

跑法：
  python3 mcp_server.py                                  # stdio（默认，行为不变）
  python3 mcp_server.py --http --host 127.0.0.1 --port 8897   # streamable-http，端点 /mcp

依赖：官方 `mcp` Python SDK（仅此一项）。v2（mcp.server.mcpserver.MCPServer）与
v1（mcp.server.fastmcp.FastMCP）都支持，谁的 API 在就用谁的。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# 扫描逻辑只从 mcp_audit 来：这里不做任何判定上的二次解释，避免两条入口结论漂移。
sys.path.insert(0, str(Path(__file__).resolve().parent))
import mcp_audit  # noqa: E402

try:  # mcp >= 2：FastMCP 改名为 MCPServer
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # pragma: no cover - mcp < 2
    try:
        from mcp.server.fastmcp import FastMCP as _Server
    except ImportError:  # SDK 没装：给出能照着做的报错，而不是 ImportError 栈
        _Server = None  # type: ignore[assignment]

TOOL_NAME = "scan_mcp_server"

# 仓库原先没有版本号标记（无 pyproject、无 git tag）。server.json 需要 semver，
# 这里定一处作为单一出处，测试里断言 server.json 与它一致，避免两边漂。
__version__ = "0.2.0"

# streamable-http 的端点路径固定为 /mcp：server.json 的 remotes[].url 末尾必须与它一致。
HTTP_PATH = "/mcp"
DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 8000
# 严重度对外用小写；但**保留 CRITICAL/INFO 这两级**——把它们压成 high/low 会把
# "RCE 面"和"提示级线索"报成同一档次，那是失真。
_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
             "LOW": "low", "INFO": "info"}
_ALLOWED_SEVERITY = set(_SEVERITY.values())


def _finding_dict(f) -> dict:
    return {
        "severity": _SEVERITY.get(str(f.severity).upper(), "info"),
        "rule": f.rule,
        "file": f.file,
        "line": f.line,
        # 扫描器产出的是"人话描述"而非源码片段；字段名沿用契约里的 snippet
        "snippet": f.desc,
    }


def scan_report(path: str, include_tests: bool = False) -> dict:
    """审计一个本地文件/目录，返回可直接序列化的结果（结构化错误也走这里）。"""
    target = Path(str(path)).expanduser()
    # 先判绝对路径：相对路径在不同 cwd 下指向不同东西，返回的结果没法复核
    if not target.is_absolute():
        return {"target": str(path), "error": "path_not_absolute",
                "message": f"需要绝对路径（收到: {path}）", "finding_count": 0,
                "findings": [], "scanned_files": 0}
    if not target.exists():
        return {"target": str(path), "error": "path_not_found",
                "message": f"目标不存在: {target}", "finding_count": 0,
                "findings": [], "scanned_files": 0}

    try:
        scanned = mcp_audit.collect_targets(target, include_tests=include_tests)
        findings = mcp_audit.scan_target(target, include_tests=include_tests)
    except Exception as e:  # 兜底：任何意外都返回结构化错误，不让 agent 端看到栈
        return {"target": str(target), "error": "scan_failed",
                "message": f"{type(e).__name__}: {e}", "finding_count": 0,
                "findings": [], "scanned_files": 0}

    return {
        "target": str(target),
        "finding_count": len(findings),
        "findings": [_finding_dict(f) for f in findings],
        "scanned_files": len(scanned),
    }


def build_server():
    """构造 server（测试直接用它，不需要起进程）。"""
    if _Server is None:  # pragma: no cover
        raise SystemExit(
            "缺少 mcp SDK：请在 venv 里 `pip install mcp` 后重试"
            "（本机系统 python 请不要装包）")
    # version 要跟 server.json 对齐：注册表按它做版本比对，留空会显示成空串。
    _kwargs = dict(
        name="mcp-audit",
        instructions=("审计 MCP server 项目的安全风险：命令注入、越权文件读写、"
                      "敏感信息泄露、危险权限、tool 描述面的 prompt injection。"),
    )
    try:
        server = _Server(version=__version__, **_kwargs)
    except TypeError:  # pragma: no cover - mcp v1 的 FastMCP 不接受 version
        server = _Server(**_kwargs)

    @server.tool(name=TOOL_NAME,
                 description="审计一个 MCP server 项目（本地路径）的安全风险，返回结构化风险清单")
    def scan_mcp_server(path: str, include_tests: bool = False) -> str:
        """审计一个 MCP server 项目（本地路径）的安全风险，返回结构化风险清单。

        参数：
          path: 要扫描的本地文件或目录的绝对路径
          include_tests: 是否同时扫描测试/fixture 文件（默认 false）
        """
        return json.dumps(scan_report(path, include_tests),
                          ensure_ascii=False, indent=2)

    return server


def _run_streamable_http(server, host: str, port: int) -> None:
    """以 streamable-http 起服务；端点固定 HTTP_PATH。

    mcp v2 的 MCPServer.run 直接接 host/port/streamable_http_path；
    v1 的 FastMCP 不接这些 kwargs，只能走 mcp.settings —— 两代都要能跑。
    """
    try:
        server.run("streamable-http", host=host, port=port, streamable_http_path=HTTP_PATH)
    except TypeError:  # pragma: no cover - 仅 mcp < 2
        import mcp.settings as _settings

        _settings.host = host
        _settings.port = port
        server.run("streamable-http")


def main(argv: list[str] | None = None) -> None:
    import argparse

    ap = argparse.ArgumentParser(
        description="mcp-audit MCP server（默认 stdio；--http 走 streamable-http，端点 /mcp）")
    ap.add_argument("--http", action="store_true", help="用 streamable-http 起服务（默认 stdio）")
    ap.add_argument("--host", default=DEFAULT_HTTP_HOST, help=f"HTTP 监听地址（默认 {DEFAULT_HTTP_HOST}）")
    ap.add_argument("--port", type=int, default=DEFAULT_HTTP_PORT,
                    help=f"HTTP 监听端口（默认 {DEFAULT_HTTP_PORT}）")
    args = ap.parse_args(argv)

    server = build_server()
    if args.http:
        _run_streamable_http(server, args.host, args.port)
        return
    if args.host != DEFAULT_HTTP_HOST or args.port != DEFAULT_HTTP_PORT:
        # stdio 模式不看 host/port；提示到 stderr，绝不污染 stdout（那是协议通道）
        print("提示：--host/--port 只在 --http 下生效，本次仍走 stdio", file=sys.stderr)
    server.run("stdio")


if __name__ == "__main__":
    main()

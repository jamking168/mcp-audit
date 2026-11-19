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
__version__ = "0.3.0"

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


# ---------------- 访问日志（JSON-RPC 级，2026-11-17 需求单 mcp-access-log） ----------------
# 为什么要它：uvicorn 只记方法/路径/状态码，日志里根本没有 tools/list、tools/call、initialize
# 这些字符串，于是「被看见」（62 个 IP、214 次请求）和「被用」（真实 MCP 客户端握手）分不开。
# 硬边界：**只记元数据，绝不落请求体原文、参数值、响应内容** —— tools/call 的 arguments
# 可能含用户私密内容。
LOG_DIR = Path(__file__).resolve().parent / "logs"
ACCESS_LOG = LOG_DIR / "mcp_access.jsonl"
ACCESS_LOG_MAX_BYTES = 20 * 1024 * 1024     # 超过就轮转
ACCESS_LOG_KEEP_DAYS = 7
_BODY_LIMIT = 256 * 1024                    # 只为解析 method/clientInfo，读这么多就够


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _header(scope, name: str) -> str:
    for k, v in scope.get("headers") or []:
        if k.decode("latin-1").lower() == name.lower():
            return v.decode("latin-1", "replace")
    return ""


def _client_ip(scope) -> str:
    """取 X-Forwarded-For 第一跳（反代后面），没有则用连接对端地址。"""
    xff = _header(scope, "x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    client = scope.get("client") or ("", 0)
    return str(client[0] or "")


def _rpc_meta(body: bytes) -> dict:
    """从请求体里只抠白名单字段：method / params.name / params.clientInfo.。

    这是**唯一**接触请求内容的地方，其余一律丢进垃圾桶（不进返回值、不进日志）。
    """
    meta: dict[str, str | None] = {"method": None, "tool": None,
                                    "client": None, "client_ver": None}
    if not body:
        return meta
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return meta            # 非法 JSON：方法记为 null，不影响请求处理
    if isinstance(data, list):  # JSON-RPC batch
        data = data[0] if data and isinstance(data[0], dict) else {}
    if not isinstance(data, dict):
        return meta
    method = data.get("method")
    meta["method"] = method if isinstance(method, str) else None
    params = data.get("params")
    if isinstance(params, dict):
        name = params.get("name")
        meta["tool"] = name if isinstance(name, str) else None
        ci = params.get("clientInfo")
        if isinstance(ci, dict):
            c = ci.get("name")
            v = ci.get("version")
            meta["client"] = c if isinstance(c, str) else None
            meta["client_ver"] = v if isinstance(v, str) else None
    return meta


def _rotate_if_needed(path: Path) -> None:
    """超过 20MB 换一个 .1 文件，并删掉 7 天前的轮转件（只删自己这个前缀）。"""
    try:
        if path.exists() and path.stat().st_size > ACCESS_LOG_MAX_BYTES:
            path.replace(path.with_suffix(path.suffix + ".1"))
    except OSError:
        return
    import time
    cutoff = time.time() - ACCESS_LOG_KEEP_DAYS * 86400
    try:
        for old in path.parent.glob(path.name + "*"):
            if old == path:
                continue
            if old.stat().st_mtime < cutoff:
                old.unlink()
    except OSError:
        pass


def write_access_record(rec: dict, path: Path = ACCESS_LOG) -> None:
    """一行一个 JSON。写失败只打 stderr —— 日志不能影响请求处理。"""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _rotate_if_needed(path)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:  # noqa: BLE001
        print(f"mcp_access log failed: {type(e).__name__}: {e}", file=sys.stderr)


class AccessLogMiddleware:
    """纯 ASGI 中间件：只在 HTTP_PATH 上记录元数据，其余请求原样穿透。"""

    def __init__(self, app, path: str = HTTP_PATH, log_path: Path = ACCESS_LOG):
        self.app = app
        self.path = path
        self.log_path = log_path

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("path") != self.path:
            return await self.app(scope, receive, send)

        body = bytearray()
        state = {"truncated": False, "status": None}

        async def _recv():
            msg = await receive()
            if msg.get("type") == "http.request" and not state["truncated"]:
                chunk = msg.get("body") or b""
                if len(body) + len(chunk) <= _BODY_LIMIT:
                    body.extend(chunk)
                else:
                    state["truncated"] = True
            return msg

        async def _send(msg):
            if msg.get("type") == "http.response.start":
                state["status"] = msg.get("status")
            await send(msg)

        try:
            await self.app(scope, _recv, _send)
        finally:
            meta = _rpc_meta(bytes(body))
            write_access_record({
                "ts": _now_iso(),
                "ip": _client_ip(scope),
                "ua": _header(scope, "user-agent")[:200],
                "method": meta["method"],
                "client": meta["client"],
                "client_ver": meta["client_ver"],
                "tool": meta["tool"],
                "status": state["status"],
                "sid_present": bool(_header(scope, "mcp-session-id")),
            }, self.log_path)


def _run_streamable_http(server, host: str, port: int) -> None:
    """以 streamable-http 起服务；端点固定 HTTP_PATH。

    2026-11-17：改为自己起 uvicorn，好把 AccessLogMiddleware 包在 SDK 造的 ASGI app 外面
    （SDK 的 server.run() 不给挂中间件的口子）。端点、监听地址、端口语义与之前完全一致。
    """
    app = None
    try:
        app = server.streamable_http_app(streamable_http_path=HTTP_PATH)
    except (AttributeError, TypeError):  # pragma: no cover - 老 SDK 没有这个方法
        app = None

    if app is not None:
        import uvicorn

        uvicorn.run(AccessLogMiddleware(app, path=HTTP_PATH), host=host, port=port,
                    log_level="info")
        return

    try:  # pragma: no cover - 兜底：维持原行为（无访问日志）
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

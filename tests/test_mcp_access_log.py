#!/usr/bin/env python3
"""mcp-audit 的 JSON-RPC 访问日志（2026-11-17 需求单 · mcp-access-log）。

钉四件事：
  1. 只记白名单元数据：method / params.name / params.clientInfo / status / ip / ua / sid_present
  2. **绝不落请求体原文与参数值** —— tools/call 的 arguments 一个字都不许进日志
  3. 非法 JSON 不崩、不把原文写进去（method 记 null）
  4. X-Forwarded-For 第一跳优先；非 /mcp 路径原样穿透、不记录

用纯 ASGI 直驱（本机 venv 没有 httpx，起不了 starlette TestClient），全部 tempdir。
"""
import asyncio
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import mcp_server as srv  # noqa: E402


def make_scope(path="/mcp", headers=None, client=("10.0.0.9", 54321)):
    return {"type": "http", "path": path, "method": "POST",
            "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()],
            "client": client}


def run_middleware(mw, scope, body=b"", status=200):
    """驱动 ASGI 一次：把 body 喂进去，收集响应状态。"""
    sent = []
    chunks = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return chunks.pop(0) if chunks else {"type": "http.disconnect"}

    async def send(msg):
        sent.append(msg)

    async def app(scope_, receive_, send_):
        await receive_()                      # 真实 app 会读请求体
        await send_({"type": "http.response.start", "status": status, "headers": []})
        await send_({"type": "http.response.body", "body": b"{}"})

    asyncio.run(mw(scope, receive, send))
    return sent


class Base(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.dir = pathlib.Path(td.name)
        self.log = self.dir / "mcp_access.jsonl"

    def lines(self):
        if not self.log.exists():
            return []
        return [json.loads(l) for l in self.log.read_text(encoding="utf-8").splitlines() if l.strip()]

    def mw(self, status=200, path="/mcp"):
        async def app(scope, receive, send):
            await receive()
            await send({"type": "http.response.start", "status": status, "headers": []})
            await send({"type": "http.response.body", "body": b"{}"})
        return srv.AccessLogMiddleware(app, path=path, log_path=self.log)


class TestRpcMeta(unittest.TestCase):
    def test_initialize_fields(self):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"clientInfo": {"name": "claude-ai", "version": "0.1.9",
                                                     "extra": "不该进日志"}}}).encode()
        m = srv._rpc_meta(body)
        self.assertEqual(m["method"], "initialize")
        self.assertEqual(m["client"], "claude-ai")
        self.assertEqual(m["client_ver"], "0.1.9")
        self.assertIsNone(m["tool"])

    def test_tools_call_keeps_name_only(self):
        body = json.dumps({"method": "tools/call",
                           "params": {"name": "scan_mcp_server",
                                      "arguments": {"path": "/secret/path", "token": "sk-XXX"}}}).encode()
        m = srv._rpc_meta(body)
        self.assertEqual(m["method"], "tools/call")
        self.assertEqual(m["tool"], "scan_mcp_server")
        self.assertNotIn("arguments", json.dumps(m))
        self.assertNotIn("sk-XXX", json.dumps(m))

    def test_bad_json_is_null_not_crash(self):
        m = srv._rpc_meta(b"{not json")
        self.assertIsNone(m["method"])

    def test_empty_body(self):
        self.assertIsNone(srv._rpc_meta(b"")["method"])

    def test_batch_takes_first(self):
        body = json.dumps([{"method": "tools/list"}, {"method": "tools/call"}]).encode()
        self.assertEqual(srv._rpc_meta(body)["method"], "tools/list")


class TestMiddleware(Base):
    def test_writes_all_fields(self):
        body = json.dumps({"method": "tools/call", "params": {
            "name": "scan_mcp_server",
            "arguments": {"path": "/tmp/x", "secret": "不该出现"}},
            "clientInfo": {"name": "x"}}).encode()
        run_middleware(self.mw(status=200), make_scope(headers={
            "user-agent": "test-agent/1.0", "mcp-session-id": "abc123",
            "x-forwarded-for": "1.2.3.4, 10.0.0.1"}), body)
        recs = self.lines()
        self.assertEqual(len(recs), 1)
        r = recs[0]
        for key in ("ts", "ip", "ua", "method", "client", "client_ver", "tool", "status", "sid_present"):
            self.assertIn(key, r)
        self.assertEqual(r["ip"], "1.2.3.4")
        self.assertEqual(r["ua"], "test-agent/1.0")
        self.assertEqual(r["method"], "tools/call")
        self.assertEqual(r["tool"], "scan_mcp_server")
        self.assertEqual(r["status"], 200)
        self.assertTrue(r["sid_present"])

    def test_never_writes_body_or_arguments(self):
        raw = ('POSTBODY-MARKER {"method":"tools/call","params":{"name":"scan_mcp_server",'
               '"arguments":{"path":"/home/jam/secret","token":"sk-live-XXX"}}}')
        run_middleware(self.mw(), make_scope(), raw.encode())
        text = self.log.read_text(encoding="utf-8")
        self.assertNotIn("POSTBODY-MARKER", text)
        self.assertNotIn("sk-live-XXX", text)
        self.assertNotIn("/home/jam/secret", text)
        self.assertNotIn("arguments", text)

    def test_no_xff_uses_peer(self):
        run_middleware(self.mw(), make_scope(client=("203.0.113.7", 1234)), b'{"method":"initialize"}')
        self.assertEqual(self.lines()[0]["ip"], "203.0.113.7")

    def test_sid_absent_is_false(self):
        run_middleware(self.mw(), make_scope(), b'{"method":"tools/list"}')
        self.assertFalse(self.lines()[0]["sid_present"])

    def test_bad_json_still_200_and_logged_null(self):
        sent = run_middleware(self.mw(status=400), make_scope(), b"{oops")
        self.assertTrue(any(m.get("status") == 400 for m in sent))
        r = self.lines()[0]
        self.assertIsNone(r["method"])
        self.assertEqual(r["status"], 400)

    def test_other_paths_pass_through_without_logging(self):
        run_middleware(self.mw(), make_scope(path="/healthz"), b'{"method":"x"}')
        self.assertEqual(self.lines(), [])

    def test_log_failure_does_not_raise(self):
        # 把日志路径指向一个不可写的位置（父路径是文件）→ 必须静默失败
        bad = self.dir / "notadir"
        bad.write_text("x", encoding="utf-8")

        async def app(scope, receive, send):
            await receive()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"{}"})

        mw = srv.AccessLogMiddleware(app, log_path=bad / "sub" / "a.jsonl")
        run_middleware(mw, make_scope(), b'{"method":"initialize"}')   # 不抛异常即通过


class TestRotation(Base):
    def test_rotate_when_over_limit(self):
        self.log.write_text("x" * 10, encoding="utf-8")
        old = srv.ACCESS_LOG_MAX_BYTES
        try:
            srv.ACCESS_LOG_MAX_BYTES = 5
            srv._rotate_if_needed(self.log)
        finally:
            srv.ACCESS_LOG_MAX_BYTES = old
        self.assertFalse(self.log.exists())
        self.assertTrue((self.dir / "mcp_access.jsonl.1").exists())


if __name__ == "__main__":
    unittest.main()

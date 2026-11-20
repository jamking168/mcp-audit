#!/usr/bin/env python3
"""mcp_server（stdio MCP 包装层）测试。

跑法（两种都行，不强制装 pytest）：
  python3 -m unittest discover -s tests -v
  python3 -m pytest tests -q          # 装了 pytest 时

没装 mcp SDK 时，涉及 SDK 的 3 个用例自动 skip（不是失败）；handler 逻辑的用例照常跑。
覆盖需求单 §2.1 三条：① tools/list 恰好一个 tool；② 高危 fixture → finding_count>0 且 severity 合法；
③ 不存在的路径 → 结构化错误，不抛栈。
"""
import asyncio
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SAMPLE_VULN = HERE / "sample_vuln.py"

sys.path.insert(0, str(ROOT))
import mcp_server  # noqa: E402

try:
    import mcp  # noqa: F401
    HAS_MCP = True
    MCP_IMPORT_ERROR = ""
except Exception as e:  # pragma: no cover
    HAS_MCP = False
    MCP_IMPORT_ERROR = f"{type(e).__name__}: {e}"

VALID_SEVERITY = {"critical", "high", "medium", "low", "info"}


class TestScanReport(unittest.TestCase):
    """不依赖 SDK：把 handler 逻辑钉住。"""

    def test_scan_report_on_vuln_fixture(self):
        report = mcp_server.scan_report(str(SAMPLE_VULN))
        self.assertGreater(report["finding_count"], 0, report)
        self.assertEqual(report["scanned_files"], 1)
        self.assertTrue({f["severity"] for f in report["findings"]} <= VALID_SEVERITY)
        # 夹具里 os.system + shell=True 必然命中 CRITICAL
        self.assertTrue(any(f["severity"] == "critical" for f in report["findings"]))
        for f in report["findings"]:
            self.assertEqual(set(f), {"severity", "rule", "file", "line", "snippet"})

    def test_scan_report_missing_path_is_structured_error(self):
        report = mcp_server.scan_report("/definitely/not/here/xyz")
        self.assertEqual(report["error"], "path_not_found")
        self.assertEqual(report["finding_count"], 0)
        self.assertEqual(report["findings"], [])
        self.assertIn("不存在", report["message"])

    def test_scan_report_rejects_relative_path(self):
        report = mcp_server.scan_report("relative/dir")
        self.assertEqual(report["error"], "path_not_absolute")

    def test_scan_report_include_tests_toggle(self):
        """默认跳过 tests/，include_tests=True 才扫：与 CLI 的 collect_targets 行为一致。"""
        without = mcp_server.scan_report(str(ROOT), include_tests=False)
        with_tests = mcp_server.scan_report(str(ROOT), include_tests=True)
        self.assertGreater(with_tests["scanned_files"], without["scanned_files"])
        self.assertEqual(with_tests["target"], without["target"])
        self.assertEqual(with_tests["target"], str(ROOT))


@unittest.skipUnless(HAS_MCP, f"未安装 mcp SDK（pip install mcp）：{MCP_IMPORT_ERROR}")
class TestToolSurface(unittest.TestCase):
    """需要 mcp SDK：从 server 对象上取 tool 面，等价于 tools/list。"""

    def setUp(self):
        self.server = mcp_server.build_server()

    def test_tool_list_has_both_tools(self):
        tools = asyncio.run(self.server.list_tools())
        names = sorted(t.name for t in tools)
        self.assertEqual(names, ["explain_rule", "list_rules", "scan_mcp_server", "scan_public_repo", "scan_to_sarif"], names)

        by_name = {t.name: t for t in tools}

        schema = (getattr(by_name["scan_mcp_server"], "inputSchema", None)
                  or getattr(by_name["scan_mcp_server"], "input_schema"))
        self.assertEqual(schema["properties"]["path"]["type"], "string")
        self.assertEqual(schema["properties"]["include_tests"]["type"], "boolean")
        self.assertIn("path", schema.get("required", []))

        rschema = (getattr(by_name["scan_public_repo"], "inputSchema", None)
                   or getattr(by_name["scan_public_repo"], "input_schema"))
        self.assertEqual(rschema["properties"]["repo_url"]["type"], "string")
        self.assertIn("repo_url", rschema.get("required", []))
        # 远程工具不能暴露本地路径参数，否则又把不可用的口子装回去
        self.assertNotIn("path", rschema["properties"])

    def test_tool_call_on_vuln_fixture(self):
        result = asyncio.run(self.server.call_tool(
            "scan_mcp_server", {"path": str(SAMPLE_VULN)}))
        payload = json.loads(result.content[0].text)
        self.assertGreater(payload["finding_count"], 0, payload)
        self.assertEqual(payload["scanned_files"], 1)
        self.assertTrue(all(f["severity"] in VALID_SEVERITY for f in payload["findings"]))

    def test_tool_call_missing_path_returns_error_not_exception(self):
        result = asyncio.run(self.server.call_tool(
            "scan_mcp_server", {"path": "/definitely/not/here/xyz"}))
        payload = json.loads(result.content[0].text)
        self.assertEqual(payload["error"], "path_not_found")
        self.assertEqual(payload["finding_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestTransportSelection(unittest.TestCase):
    """R1：默认 stdio 不变；--http 走 streamable-http 且端点固定 /mcp（不依赖 SDK，打桩即可）。"""

    def setUp(self):
        self.calls = []

        class FakeServer:
            def run(self, transport, **kw):
                self_calls = self  # noqa: F841
                TestTransportSelection.record.append((transport, kw))

        TestTransportSelection.record = []
        self.record = TestTransportSelection.record
        self.fake = FakeServer()

    def _run_main(self, argv, patch_build=True):
        import contextlib
        import io
        from unittest import mock
        out, err = io.StringIO(), io.StringIO()
        targets = ([mock.patch.object(mcp_server, "build_server", lambda: self.fake)]
                   if patch_build else [])
        with contextlib.ExitStack() as st:
            for t in targets:
                st.enter_context(t)
            st.enter_context(mock.patch.object(sys, "argv", ["mcp_server.py", *argv]))
            st.enter_context(contextlib.redirect_stdout(out))
            st.enter_context(contextlib.redirect_stderr(err))
            mcp_server.main(argv)
        return out.getvalue(), err.getvalue()

    def test_stdio_is_default_and_unchanged(self):
        """无参数 → run("stdio")，且不传任何传输 kwargs（stdio 协议通道不能被污染）。"""
        out, err = self._run_main([])
        self.assertEqual(self.record, [("stdio", {})])
        self.assertEqual(out, "", "stdio 模式不许往 stdout 写任何东西")
        self.assertEqual(err, "")

    def test_http_mode_uses_streamable_http_on_mcp_path(self):
        self._run_main(["--http", "--host", "127.0.0.1", "--port", "8897"])
        self.assertEqual(len(self.record), 1)
        transport, kw = self.record[0]
        self.assertEqual(transport, "streamable-http")
        self.assertEqual(kw["host"], "127.0.0.1")
        self.assertEqual(kw["port"], 8897)
        self.assertEqual(kw["streamable_http_path"], "/mcp")
        self.assertEqual(mcp_server.HTTP_PATH, "/mcp")

    def test_http_defaults_are_loopback_8000(self):
        self._run_main(["--http"])
        transport, kw = self.record[0]
        self.assertEqual(transport, "streamable-http")
        self.assertEqual((kw["host"], kw["port"]), ("127.0.0.1", 8000))

    def test_port_without_http_stays_stdio_and_warns_on_stderr(self):
        """--port 单独给不给 --http：仍 stdio，提示只进 stderr。"""
        out, err = self._run_main(["--port", "8897"])
        self.assertEqual(self.record, [("stdio", {})])
        self.assertEqual(out, "")
        self.assertIn("--http", err)


class TestServerManifest(unittest.TestCase):
    """R2：server.json 必须是官方 registry schema 认识的字段，且版本与代码一致。"""

    def setUp(self):
        self.path = ROOT / "server.json"
        self.data = json.loads(self.path.read_text(encoding="utf-8"))

    def test_required_fields_and_no_invented_keys(self):
        allowed = {"$schema", "_meta", "description", "icons", "name", "packages",
                   "remotes", "repository", "title", "version", "websiteUrl"}
        self.assertTrue({"name", "description", "version"} <= set(self.data))
        self.assertEqual(set(self.data) - allowed, set(), "出现 schema 里没有的字段")

    def test_name_is_reverse_dns_with_one_slash(self):
        import re
        name = self.data["name"]
        self.assertEqual(name.count("/"), 1, name)
        self.assertRegex(name, r"^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$")

    def test_version_matches_code(self):
        self.assertEqual(self.data["version"], mcp_server.__version__)

    def test_remote_is_streamable_http_ending_with_mcp(self):
        remotes = self.data["remotes"]
        self.assertEqual(len(remotes), 1)
        self.assertEqual(remotes[0]["type"], "streamable-http")
        self.assertTrue(remotes[0]["url"].startswith("https://"))
        self.assertTrue(remotes[0]["url"].rstrip("/").endswith(mcp_server.HTTP_PATH))

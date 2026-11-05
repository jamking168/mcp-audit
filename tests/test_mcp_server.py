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

    def test_tool_list_has_exactly_scan_mcp_server(self):
        tools = asyncio.run(self.server.list_tools())
        self.assertEqual([t.name for t in tools], ["scan_mcp_server"])
        schema = getattr(tools[0], "inputSchema", None) or getattr(tools[0], "input_schema")
        self.assertEqual(schema["properties"]["path"]["type"], "string")
        self.assertEqual(schema["properties"]["include_tests"]["type"], "boolean")
        self.assertIn("path", schema.get("required", []))

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

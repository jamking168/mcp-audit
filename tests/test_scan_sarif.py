#!/usr/bin/env python3
"""SARIF 输出契约：客户 CI 直接上传 GitHub code scanning，格式错一个字段就白交付。

跑法：python3 tests/test_scan_sarif.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

import scan_repo  # noqa: E402


class TestSarif(unittest.TestCase):
    def test_severity_mapping(self) -> None:
        res = {"findings": [
            {"severity": "critical", "rule": "eval", "file": "a.js", "line": 3, "snippet": "x"},
            {"severity": "high", "rule": "shell", "file": "b.py", "line": 7, "snippet": "y"},
            {"severity": "medium", "rule": "net", "file": "c.py", "line": 1, "snippet": "z"},
            {"severity": "low", "rule": "os", "file": "d.py", "line": 2, "snippet": "w"},
        ]}
        sarif = scan_repo.to_sarif(res, "https://github.com/o/r")
        run = sarif["runs"][0]
        levels = {r["ruleId"]: r["level"] for r in run["results"]}
        self.assertEqual(levels, {"eval": "error", "shell": "error",
                                  "net": "warning", "os": "note"})
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("$schema", sarif)
        self.assertEqual(run["tool"]["driver"]["name"], "mcp-audit")

    def test_result_shape(self) -> None:
        sarif = scan_repo.to_sarif(
            {"findings": [{"severity": "high", "rule": "call:subprocess.run",
                           "file": "pkg/a.py", "line": 25, "snippet": "子进程调用"}]},
            "https://github.com/o/r")
        r = sarif["runs"][0]["results"][0]
        loc = r["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "pkg/a.py")
        self.assertEqual(loc["region"]["startLine"], 25)
        self.assertTrue(r["message"]["text"])
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["rules"][0]["id"],
                         "call:subprocess.run")

    def test_empty_scan_is_valid(self) -> None:
        sarif = scan_repo.to_sarif({"findings": [], "error": "clone_failed"}, "/tmp/x")
        self.assertEqual(sarif["runs"][0]["results"], [])
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["rules"], [])

    def test_cli_writes_sarif(self) -> None:
        out = os.path.join(tempfile.mkdtemp(prefix="sarif-"), "out.sarif")
        rc = subprocess.run([sys.executable, os.path.join(BASE, "scan_repo.py"),
                             os.path.abspath(os.path.join(BASE, "tests")), "--sarif", out],
                            capture_output=True, text=True)
        self.assertEqual(rc.returncode, 0, rc.stderr)
        with open(out, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["version"], "2.1.0")
        self.assertIsInstance(data["runs"][0]["results"], list)

    def test_standalone_cli_writes_sarif(self) -> None:
        """客户 vendor 的是 mcp_audit.py（stdlib-only），它的 --sarif 必须同样能用。

        用一个自造的样本文件做目标：mcp_audit.py 自己不调用危险函数，
        扫它必然 0 条，断言就变成假绿。样本里 os.system 是确定性命中。
        """
        tmpdir = tempfile.mkdtemp(prefix="sarif-solo-")
        sample = os.path.join(tmpdir, "bad.py")
        with open(sample, "w", encoding="utf-8") as fh:
            fh.write('import os\n\ndef run(cmd):\n    os.system("ls " + cmd)\n')
        out = os.path.join(tmpdir, "out.sarif")
        rc = subprocess.run([sys.executable, os.path.join(BASE, "mcp_audit.py"),
                             sample, "--sarif", out],
                            capture_output=True, text=True)
        self.assertEqual(rc.returncode, 0, rc.stderr)
        with open(out, encoding="utf-8") as fh:
            data = json.load(fh)
        run = data["runs"][0]
        self.assertTrue(run["results"], "样本含 os.system，0 条说明 --sarif 没跑通")
        self.assertTrue(all(r["level"] in ("error", "warning", "note") for r in run["results"]))
        self.assertTrue(any(r["ruleId"] == "call:os.system" for r in run["results"]))


if __name__ == "__main__":
    unittest.main()

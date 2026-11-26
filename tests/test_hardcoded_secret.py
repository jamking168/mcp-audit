#!/usr/bin/env python3
"""硬编码密钥检测（hardcoded_secret）单测。

背景：2026-11-26 实测发现，README 宣称能查「泄露的密钥」，但扫描只会看
`os.getenv("API_KEY")`，密钥直接写进代码时完全漏报；而且 JS 去噪会把字符串
字面量替换成 ""，规则必须用原始行匹配才抓得到。
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import mcp_audit as ma  # noqa: E402

PAT = ma.GENERIC_PATTERNS["hardcoded_secret"][0]


class TestRegex(unittest.TestCase):
    def test_provider_shapes(self):
        for s in (
            'const k = "sk-live-9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c";',
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
            'token: "ghp_abcdefghijklmnopqrstuvwxyz0123456789"',
            'slack = "xoxb-1234567890-abcdefghij"',
            'key = "AIzaSyD-1234567890abcdefghijklmnopqrstu"',
            '-----BEGIN RSA PRIVATE KEY-----',
        ):
            self.assertTrue(PAT.search(s), s)

    def test_generic_assignments(self):
        for s in ('api_key = "9f8a7b6c5d4e3f2a1b0c9d"',
                  'SECRET: "Zx81kLmNoPqRsTuV"',
                  'password="hunter2hunter2hunter2"'):
            self.assertTrue(PAT.search(s), s)

    def test_placeholders_ignored(self):
        for s in ('api_key = "your_key_here_please"',
                  'API_KEY = "changeme_changeme_changeme"',
                  'token = "xxxxxxxxxxxxxxxxxxxx"',
                  'secret = "example_value_here"',
                  'password = "placeholder_pass"'):
            self.assertFalse(PAT.search(s), s)

    def test_short_values_ignored(self):
        self.assertFalse(PAT.search('api_key = "abc123"'))
        self.assertFalse(PAT.search('token = os.getenv("TOKEN")'))


class TestEndToEnd(unittest.TestCase):
    def _scan(self, name: str, body: str):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / name
            p.write_text(body, encoding="utf-8")
            fs = ma.scan_target(Path(d), max_per_rule=5)
        return [f for f in fs if f.rule == "hardcoded_secret"]

    def test_js_literal_is_found(self):
        """回归：JS 去噪把字符串替换成 ""，这条曾导致密钥完全抓不到。"""
        hits = self._scan("server.js", 'const KEY = "sk-live-9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c";\n')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "HIGH")

    def test_python_literal_is_found(self):
        hits = self._scan("conf.py", 'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        self.assertEqual(len(hits), 1)

    def test_clean_file_has_no_hits(self):
        hits = self._scan("ok.py", 'import os\nKEY = os.getenv("API_KEY")\n')
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

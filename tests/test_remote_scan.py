"""remote_scan 单测：URL 白名单、速率限制、克隆失败/超限/清理。不联网。"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import remote_scan as rs  # noqa: E402


class TestValidateUrl(unittest.TestCase):
    def test_accepts_three_hosts(self):
        for u in ("https://github.com/a/b", "https://gitlab.com/a/b",
                  "https://gitee.com/a/b", "https://github.com/a/b/"):
            self.assertEqual(rs.validate_repo_url(u), "", u)

    def test_rejects_non_https(self):
        self.assertIn("https", rs.validate_repo_url("http://github.com/a/b"))
        self.assertIn("https", rs.validate_repo_url("ssh://git@github.com/a/b"))

    def test_rejects_unknown_host(self):
        for u in ("https://evil.com/a/b", "https://127.0.0.1/a/b",
                  "https://github.com.evil.com/a/b"):
            self.assertIn("只支持", rs.validate_repo_url(u))

    def test_rejects_credentials_port_query_fragment(self):
        self.assertIn("凭证", rs.validate_repo_url("https://u:p@github.com/a/b"))
        self.assertIn("端口", rs.validate_repo_url("https://github.com:8080/a/b"))
        self.assertIn("查询参数", rs.validate_repo_url("https://github.com/a/b?x=1"))
        self.assertIn("查询参数", rs.validate_repo_url("https://github.com/a/b#readme"))

    def test_rejects_bad_path_shape(self):
        self.assertIn("owner/repo", rs.validate_repo_url("https://github.com/only"))
        self.assertIn("owner/repo", rs.validate_repo_url("https://github.com/a/b/tree/main"))

    def test_rejects_empty_and_overlong(self):
        self.assertIn("不能为空", rs.validate_repo_url(""))
        self.assertIn("过长", rs.validate_repo_url("https://github.com/" + "a" * 300))


class TestRateLimit(unittest.TestCase):
    def setUp(self):
        rs._recent.clear()

    def test_allows_then_blocks(self):
        for _ in range(rs.RATE_LIMIT):
            self.assertTrue(rs._rate_ok())
        self.assertFalse(rs._rate_ok())

    def test_window_slides(self):
        now = 1_000_000.0
        with mock.patch("remote_scan.time.time", return_value=now):
            for _ in range(rs.RATE_LIMIT):
                self.assertTrue(rs._rate_ok())
        with mock.patch("remote_scan.time.time", return_value=now + rs.RATE_WINDOW + 1):
            self.assertTrue(rs._rate_ok())


class TestScanPublicRepo(unittest.TestCase):
    def setUp(self):
        rs._recent.clear()

    def test_invalid_url_never_clones(self):
        with mock.patch.object(rs, "clone_repo") as cl:
            r = rs.scan_public_repo("https://evil.com/a/b", lambda p: {})
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "invalid_repo_url")
        cl.assert_not_called()

    def test_clone_failure_reports_and_cleans(self):
        with mock.patch.object(rs, "clone_repo", return_value=(False, "boom")):
            r = rs.scan_public_repo("https://github.com/a/b", lambda p: {})
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "clone_failed")

    def test_oversized_repo_rejected(self):
        def fake_clone(url, dest):
            Path(dest).mkdir(parents=True)
            return True, ""

        with mock.patch.object(rs, "clone_repo", side_effect=fake_clone), \
             mock.patch.object(rs, "_dir_mb", return_value=999.0):
            r = rs.scan_public_repo("https://github.com/a/b", lambda p: {})
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "repo_too_large")

    def test_success_passes_clone_path_and_cleans_tmp(self):
        seen = {}

        def fake_clone(url, dest):
            Path(dest).mkdir(parents=True)
            (Path(dest) / "x.py").write_text("print(1)")
            return True, ""

        def fake_summarize(path):
            seen["path"] = path
            return {"scanned_files": 1, "finding_count": 2,
                    "findings": [{"severity": "high"}] * 2}

        with mock.patch.object(rs, "clone_repo", side_effect=fake_clone):
            r = rs.scan_public_repo("https://github.com/a/b", fake_summarize)
        self.assertTrue(r["ok"])
        self.assertEqual(r["finding_count"], 2)
        self.assertTrue(os.path.isabs(seen["path"]), "传给扫描器的必须是绝对路径")
        self.assertFalse(os.path.exists(os.path.dirname(seen["path"])), "临时目录必须删掉")

    def test_rate_limited_before_clone(self):
        rs._recent.extend([time.time()] * rs.RATE_LIMIT)
        with mock.patch.object(rs, "clone_repo") as cl:
            r = rs.scan_public_repo("https://github.com/a/b", lambda p: {})
        self.assertEqual(r["error"], "rate_limited")
        cl.assert_not_called()


if __name__ == "__main__":
    unittest.main()

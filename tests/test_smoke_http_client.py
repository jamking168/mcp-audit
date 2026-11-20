"""scripts/smoke_http_client.py 的冒烟用例（2026-11-09）。

它是**对外部署**的探针，所以这里只做两件事：
1. 8897 没在监听 → skip（绝不让「没起服务」变成一片红）；
2. 在监听 → 真跑一遍三段往返，断言输出与部署文档里贴的证据一致。

注意：这条用例需要解释器里有 mcp SDK（repo 的 .venv 有；系统 python3 没有 → skip）。
"""
import os
import socket
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "smoke_http_client.py")
HOST, PORT = "127.0.0.1", 8897


def _port_open(host=HOST, port=PORT, timeout=0.3):
    with socket.socket() as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


class TestSmokeHttpClient(unittest.TestCase):
    def setUp(self):
        # 端口没起就跳过：这条用例验的是「部署起来的服务」，不是脚本语法
        if not _port_open():
            self.skipTest(f"{HOST}:{PORT} 未监听（先起 mcp_server.py --http --port {PORT}）")
        try:
            import mcp  # noqa: F401
        except ImportError:
            self.skipTest("当前解释器没有 mcp SDK（用 repo 的 .venv/bin/python -m pytest）")

    def test_three_step_roundtrip_against_live_server(self):
        r = subprocess.run([sys.executable, SCRIPT], capture_output=True, text=True, timeout=180)
        self.assertEqual(r.returncode, 0, (r.stdout + r.stderr)[-800:])
        out = r.stdout
        # 三段都要有，且与 deploy/README.md 里贴的实测证据同口径
        self.assertIn("[1] initialize -> mcp-audit", out)

        # tools/list 只校验「必备工具在位」，不锁定完整列表。
        # 2026-11-20 工具面从 1 个扩到 2 个、再到 5 个，硬编码整行会让每次扩面都误报失败。
        line = next((l for l in out.splitlines() if l.startswith("[2] tools/list")), "")
        self.assertTrue(line, "缺少 tools/list 输出：" + out[-400:])
        for must in ("scan_mcp_server", "scan_public_repo"):
            self.assertIn(must, line, line)

        self.assertIn("[3] tools/call -> keys:", out)
        self.assertIn("findings:", out)


if __name__ == "__main__":
    unittest.main()

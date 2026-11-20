#!/usr/bin/env python3
"""零依赖 stdio server 验收：协议应答、工具清单、真实扫描、错误码。

不依赖 mcp SDK，用系统 python3 跑。
跑法：python3 tests/test_mcp_server_stdlib.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(BASE, "mcp_server_stdlib.py")

_passed = 0
_failures: list[str] = []


def check(name: str, cond: bool, extra: str = "") -> None:
    global _passed
    if cond:
        _passed += 1
    else:
        _failures.append(f"{name} — {extra}" if extra else name)


def call(lines: list[dict]) -> list[dict]:
    payload = "\n".join(json.dumps(x, ensure_ascii=False) for x in lines) + "\n"
    p = subprocess.run([sys.executable, SERVER], input=payload, capture_output=True,
                       text=True, timeout=60, cwd=BASE)
    out = []
    for line in p.stdout.splitlines():
        if line.strip():
            out.append(json.loads(line))          # 任何非 JSON 输出都会在这里炸
    return out


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="stdlib-mcp-")
    bad = os.path.join(tmp, "bad.py")
    open(bad, "w", encoding="utf-8").write(
        "import os\n\ndef run(cmd):\n    os.system('ls ' + cmd)\n")

    reqs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "scan_mcp_server", "arguments": {"path": tmp}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "scan_mcp_server", "arguments": {"path": "/nope/not/here"}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
         "params": {"name": "scan_public_repo", "arguments": {"repo_url": "https://evil.example/x"}}},
        {"jsonrpc": "2.0", "id": 6, "method": "does/not/exist"},
    ]
    res = {r.get("id"): r for r in call(reqs)}

    check("通知不产生响应", 0 not in res and len(res) == 6, str(sorted(res)))
    init = res[1]["result"]
    check("initialize 回显协议版本", init["protocolVersion"] == "2025-11-25")
    check("serverInfo 名称", init["serverInfo"]["name"] == "mcp-audit")
    check("声明 tools 能力", "tools" in init["capabilities"])

    tools = res[2]["result"]["tools"]
    names = sorted(t["name"] for t in tools)
    check("工具清单", names == ["scan_mcp_server", "scan_public_repo"], str(names))
    check("scan_mcp_server 必填 path",
          tools[0]["inputSchema"]["required"] == ["path"])

    scan = res[3]["result"]
    check("真实扫描非错误", scan["isError"] is False)
    data = json.loads(scan["content"][0]["text"])
    check("扫出 os.system", data["finding_count"] >= 1)
    check("发现带规则名", any(f["rule"] == "call:os.system" for f in data["findings"]),
          str(data["findings"])[:120])

    missing = res[4]["result"]
    check("不存在的路径标错误", missing["isError"] is True)
    check("错误码 path_not_found",
          json.loads(missing["content"][0]["text"])["error"] == "path_not_found")

    bad_repo = res[5]["result"]
    check("拒绝非白名单仓库", json.loads(bad_repo["content"][0]["text"])["error"] == "bad_repo_url")

    check("未知方法 -32601", res[6]["error"]["code"] == -32601)

    print()
    if _failures:
        print(f"FAILED ({len(_failures)}): " + "; ".join(_failures))
        return 1
    print(f"OK — 零依赖 stdio server {_passed} 项断言全通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())

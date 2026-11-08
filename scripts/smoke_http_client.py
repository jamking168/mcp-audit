"""三段往返自测:initialize -> tools/list -> tools/call（对 8897 的 streamable-http 端点）"""
import asyncio, json, sys

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

URL = "http://127.0.0.1:8897/mcp"


async def main() -> int:
    async with streamable_http_client(URL) as (r, w):
        async with ClientSession(r, w) as s:
            init = await s.initialize()
            print("[1] initialize ->", init.server_info.name, init.server_info.version)

            tools = await s.list_tools()
            print("[2] tools/list ->", [t.name for t in tools.tools])
            assert any(t.name == "scan_mcp_server" for t in tools.tools), "tool missing"

            res = await s.call_tool("scan_mcp_server", {"path": "/home/jam/projects/mcp-audit"})
            body = res.content[0].text if res.content else ""
            data = json.loads(body)
            print("[3] tools/call -> keys:", sorted(data.keys()))
            print("    findings:", len(data.get("findings", [])), "| scanned:", data.get("target") or data.get("path"))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

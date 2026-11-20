#!/usr/bin/env python3
"""Deprecate an older version of top.web3project/mcp-audit in the official MCP registry.

Auth: sign a UTC timestamp with deploy/mcp-auth-key.pem, exchange for a registry JWT
(POST /v0/auth/http). Never prints the token.

Usage:
  python3 registry_deprecate_old_version.py            # dry-run: auth + show current status
  python3 registry_deprecate_old_version.py --apply    # PATCH 0.2.0 -> deprecated
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://registry.modelcontextprotocol.io"
SERVER = "top.web3project/mcp-audit"
# 可由环境变量覆盖，避免每次发版都要改脚本常量（0.4.0 发版时踩过一次）
OLD = os.environ.get("OLD_VERSION", "0.3.0")
NEW = os.environ.get("NEW_VERSION", "0.4.0")
KEY = "/home/jam/projects/mcp-audit/deploy/mcp-auth-key.pem"


def sign_timestamp() -> tuple[str, str]:
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with tempfile.TemporaryDirectory() as d:
        tsp, sig = f"{d}/ts.txt", f"{d}/sig.bin"
        with open(tsp, "w") as f:
            f.write(ts)  # no trailing newline
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", KEY, "-rawin",
                        "-in", tsp, "-out", sig], check=True, capture_output=True)
        with open(sig, "rb") as f:
            return ts, f.read().hex()


def post_json(url, payload, headers=None):
    body = json.dumps(payload).encode()
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=body, headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, json.loads(r.read().decode())


def get_json(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, json.loads(r.read().decode())


def patch_json(url, payload, token):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method="PATCH", headers={
        "Content-Type": "application/json", "Accept": "application/json",
        "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, json.loads(r.read().decode())


def main():
    apply = "--apply" in sys.argv
    ts, sig = sign_timestamp()
    st, tok = post_json(f"{BASE}/v0/auth/http",
                        {"domain": "web3project.top", "timestamp": ts,
                         "signed_timestamp": sig})
    token = tok.get("registry_token")
    print(f"auth: HTTP {st}, token={'yes' if token else 'NO'}")
    if not token:
        print("auth response keys:", sorted(tok.keys()))
        return 2

    quoted = urllib.parse.quote(SERVER, safe="")
    st, cur = get_json(f"{BASE}/v0/servers/{quoted}/versions/{OLD}")
    meta = cur.get("_meta", {}).get("io.modelcontextprotocol.registry/official", {})
    print(f"before: {OLD} status={meta.get('status')} isLatest={meta.get('isLatest')}")

    if not apply:
        print("dry-run only; pass --apply to PATCH status=deprecated")
        return 0

    try:
        st, res = patch_json(f"{BASE}/v0/servers/{quoted}/versions/{OLD}/status",
                             {"status": "deprecated",
                              "statusMessage": f"Superseded by {NEW}; same endpoint, updated title/description."},
                             token)
    except urllib.error.HTTPError as e:
        print("PATCH failed:", e.code, e.read().decode()[:400])
        return 1
    m2 = res.get("_meta", {}).get("io.modelcontextprotocol.registry/official", {})
    print(f"patch: HTTP {st} -> status={m2.get('status')} statusChangedAt={m2.get('statusChangedAt')}")

    st, chk = get_json(f"{BASE}/v0/servers/{quoted}/versions/{OLD}")
    m3 = chk.get("_meta", {}).get("io.modelcontextprotocol.registry/official", {})
    print(f"verify: {OLD} status={m3.get('status')} msg={m3.get('statusMessage')}")
    st, latest = get_json(f"{BASE}/v0/servers/{quoted}/versions/{NEW}")
    m4 = latest.get("_meta", {}).get("io.modelcontextprotocol.registry/official", {})
    print(f"verify: {NEW} status={m4.get('status')} isLatest={m4.get('isLatest')}")
    return 0 if m3.get("status") == "deprecated" else 1


if __name__ == "__main__":
    sys.exit(main())

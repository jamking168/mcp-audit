#!/usr/bin/env python3
"""等 Glama 收录页出现后，自动给 awesome-mcp-servers 的 PR 补上评分徽章。

背景：awesome-mcp-servers 的机器人要求 PR 行里带 Glama 徽章，而徽章只在
Glama 真正构建并收录该仓库后才不是 "not listed"。Glama 的构建是异步的，
人工盯不现实，所以这里轮询徽章状态，就绪后改 fork 上的 PR 分支并推送。

用法：
  python3 glama_watch.py            # 正常轮询（cron 用）
  python3 glama_watch.py --check    # 只看状态，不改任何东西
  python3 glama_watch.py --force    # 跳过状态检查，直接改（人工确认收录后）
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(BASE, ".glama-watch")
STATE = os.path.join(BASE, "state", "glama_watch.json")
BADGE_URL = "https://glama.ai/mcp/servers/jamking168/mcp-audit/badges/score.svg"
PAGE_URL = "https://glama.ai/mcp/servers/jamking168/mcp-audit"
FORK = "https://github.com/jamking168/awesome-mcp-servers.git"
BRANCH = "add-mcp-audit"
ENTRY = ("- [jamking168/mcp-audit](https://github.com/jamking168/mcp-audit) "
         "[![jamking168/mcp-audit MCP server](https://glama.ai/mcp/servers/jamking168/mcp-audit/badges/score.svg)]"
         "(https://glama.ai/mcp/servers/jamking168/mcp-audit) "
         "🐍 🏠 🍎 🪟 🐧 - Static security scanner for MCP servers: command injection, secret handling, "
         "unsafe file access and tool-poisoning patterns, with SARIF output for code scanning. "
         "Runs offline and never executes the code it reads.")
NOTIFY = "/home/jam/.hermes/profiles/alpha-scout/scripts/profile_self_delivery.py"


def listed() -> tuple[bool, str]:
    try:
        with urllib.request.urlopen(BADGE_URL, timeout=20) as r:
            svg = r.read().decode("utf-8", "replace")
    except Exception as e:
        return False, f"badge fetch failed: {type(e).__name__}"
    if "not listed on Glama" in svg:
        return False, "badge says not listed"
    return True, "badge ok"


def sh(cmd: list[str], cwd: str | None = None, timeout: int = 180) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr)[-800:]


def patch_pr() -> tuple[bool, str]:
    if not os.path.isdir(os.path.join(WORK, ".git")):
        code, out = sh(["git", "clone", "-q", "--depth", "1", "--branch", BRANCH, FORK, WORK])
        if code:
            # 分支可能还没在本地；先完整克隆再切
            code, out = sh(["git", "clone", "-q", FORK, WORK])
            if code:
                return False, "clone failed: " + out
            sh(["git", "checkout", BRANCH], cwd=WORK)
    else:
        sh(["git", "fetch", "-q", "origin", BRANCH], cwd=WORK)
        sh(["git", "checkout", "-q", BRANCH], cwd=WORK)
        sh(["git", "reset", "-q", "--hard", f"origin/{BRANCH}"], cwd=WORK)

    readme = os.path.join(WORK, "README.md")
    raw = open(readme, encoding="utf-8").read()
    if "glama.ai/mcp/servers/jamking168/mcp-audit/badges" in raw:
        return True, "already patched"
    lines = raw.split("\n")
    hit = next((i for i, l in enumerate(lines) if "[jamking168/mcp-audit]" in l), -1)
    if hit < 0:
        return False, "entry line not found"
    lines[hit] = ENTRY
    open(readme, "w", encoding="utf-8").write("\n".join(lines))
    code, out = sh(["git", "add", "README.md"], cwd=WORK)
    code, out = sh(["git", "-c", "user.name=jamking168",
                    "-c", "user.email=jamking168@users.noreply.github.com",
                    "commit", "-q", "-m", "Add Glama score badge for mcp-audit"], cwd=WORK)
    if code:
        return False, "commit failed: " + out
    code, out = sh(["git", "push", "-q", "origin", BRANCH], cwd=WORK)
    if code:
        return False, "push failed: " + out
    return True, "badge added and pushed"


def notify(text: str) -> None:
    try:
        subprocess.run(["python3", NOTIFY, "--mode", "chat", "--text", text], timeout=90, check=False)
    except Exception:
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()

    ok, why = listed()
    print(json.dumps({"listed": ok, "detail": why, "badge": BADGE_URL, "page": PAGE_URL}, ensure_ascii=False))
    if not ok and not a.force:
        return 0
    if a.check:
        return 0
    good, detail = patch_pr()
    st = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "ok": good, "detail": detail}
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    json.dump(st, open(STATE, "w"), ensure_ascii=False)
    print(json.dumps(st, ensure_ascii=False))
    if good and detail != "already patched":
        notify("[glama_watch] Glama 已收录，PR 徽章已补并推送（awesome-mcp-servers #20099）")
    return 0 if good else 1


if __name__ == "__main__":
    raise SystemExit(main())

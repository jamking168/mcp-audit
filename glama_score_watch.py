#!/usr/bin/env python3
"""盯 Glama 评分：徽章从 B 变成别的（A/…) 时推一条消息，不重复吵。

为什么要单独一个：Glama 的评分是异步重算的，发版后能看到新工具已上线，
但评分页可能还是上一次的结果；人工反复刷新没意义。
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(BASE, "state", "glama_score.json")
BADGE = "https://glama.ai/mcp/servers/jamking168/mcp-audit/badges/score.svg"
NOTIFY = "/home/jam/.hermes/profiles/alpha-scout/scripts/profile_self_delivery.py"


def rating() -> str:
    req = urllib.request.Request(BADGE, headers={"User-Agent": "score-watch/1.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        svg = r.read().decode("utf-8", "replace")
    m = re.search(r"rated ([A-F]) on Glama", svg)
    if m:
        return m.group(1)
    return "not-listed" if "not listed" in svg else "?"


def main() -> int:
    try:
        cur = rating()
    except Exception as e:
        print(json.dumps({"error": type(e).__name__}))
        return 0
    prev = ""
    try:
        prev = json.load(open(STATE, encoding="utf-8")).get("rating", "")
    except Exception:
        pass
    st = {"rating": cur, "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "prev": prev}
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    json.dump(st, open(STATE, "w"), ensure_ascii=False)
    print(json.dumps(st, ensure_ascii=False))
    if prev and cur != prev:
        try:
            subprocess.run(["python3", NOTIFY, "--mode", "chat", "--text",
                            f"[glama] 评分变化：{prev} → {cur}（mcp-audit）"], timeout=90, check=False)
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

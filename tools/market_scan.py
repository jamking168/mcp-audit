#!/usr/bin/env python3
"""对 GitHub 上高星的 MCP server 做一次真实扫描，产出市场底稿。

用途：不是做攻击，是回答「这类工具值不值得做、目标客户在哪、外联有没有话说」。
输出 JSON + 简要统计；不落任何私仓代码，扫完即删。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mcp_audit  # noqa: E402

TOKEN = open("/tmp/ghtok").read().strip() if os.path.exists("/tmp/ghtok") else ""
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "state", "market_scan.json")
SKIP = ("awesome", "list", "collection", "registry")


def api(url: str):
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "mcp-audit-market-scan",
        **({"Authorization": "token " + TOKEN} if TOKEN else {}),
    })
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def main(limit: int = 15) -> int:
    repos = []
    for page in (1, 2):
        data = api(f"https://api.github.com/search/repositories?q=topic:mcp-server&sort=stars&order=desc&per_page=30&page={page}")
        for it in data.get("items", []):
            name = it["full_name"]
            if any(s in name.lower() for s in SKIP):
                continue
            repos.append({"repo": name, "stars": it["stargazers_count"],
                          "desc": (it.get("description") or "")[:160],
                          "url": it["html_url"], "size": it.get("size", 0)})
        if len(repos) >= limit:
            break
    repos = repos[:limit]

    results = []
    tmp = tempfile.mkdtemp(prefix="mkt-")
    for i, r in enumerate(repos, 1):
        if r["size"] > 120_000:  # 太大跳过，别把磁盘吃满
            results.append({**r, "skipped": "too_large"})
            continue
        d = os.path.join(tmp, "r%d" % i)
        try:
            subprocess.run(["git", "clone", "--depth", "1", "--quiet", r["url"], d],
                           timeout=180, check=True, capture_output=True)
            fs = mcp_audit.scan_target(Path(d), include_tests=False)
            sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            rules = {}
            for f in fs:
                sev[f.severity] = sev.get(f.severity, 0) + 1
                rules[f.rule] = rules.get(f.rule, 0) + 1
            results.append({**r, "files": len(list(Path(d).rglob("*.py"))), "sev": sev,
                            "findings": len(fs),
                            "top_rules": sorted(rules.items(), key=lambda kv: -kv[1])[:6]})
        except Exception as e:  # noqa: BLE001
            results.append({**r, "error": "%s: %s" % (type(e).__name__, str(e)[:120])})
        finally:
            shutil.rmtree(d, ignore_errors=True)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump({"ts": __import__("time").strftime("%Y-%m-%dT%H:%M:%S%z"), "results": results},
              open(OUT, "w"), ensure_ascii=False, indent=1)

    ok = [r for r in results if "findings" in r]
    crit = [r for r in ok if r["sev"].get("CRITICAL")]
    print("扫描 %d 个仓库（成功 %d）" % (len(results), len(ok)))
    print("含 CRITICAL: %d/%d = %.0f%%" % (len(crit), len(ok), 100 * len(crit) / max(1, len(ok))))
    tot = sum(r["findings"] for r in ok)
    print("总 findings %d，平均 %.1f/仓库" % (tot, tot / max(1, len(ok))))
    for r in sorted(ok, key=lambda x: -(x["sev"].get("CRITICAL", 0)))[:8]:
        print("  %-42s ★%-5d CRIT %-3d HIGH %-3d  %s" % (
            r["repo"], r["stars"], r["sev"].get("CRITICAL", 0), r["sev"].get("HIGH", 0),
            ",".join(k for k, _ in r["top_rules"][:2])))
    print("结果:", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(int(sys.argv[1]) if len(sys.argv) > 1 else 15))

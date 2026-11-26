#!/usr/bin/env python3
"""GitHub Action gate：把 mcp-audit 的 JSON 结果转成注释、摘要与退出码。

为什么要单独一个文件：mcp_audit.py 的出口码永远是 0（它是给人看的 CLI），
CI 需要「有 CRITICAL 就失败」的行为，这个判断只应该在一处实现。

用法（action.yml 内部调用）：
  python3 scripts/ci_gate.py --report report.json --sarif out.sarif \
      --fail-on high --summary "$GITHUB_STEP_SUMMARY"
"""
from __future__ import annotations

import argparse
import json
import os
import sys

ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True)
    ap.add_argument("--sarif", default="")
    ap.add_argument("--fail-on", default="none", choices=["none", "critical", "high"])
    ap.add_argument("--summary", default="")
    a = ap.parse_args()

    try:
        data = json.load(open(a.report, encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        print("::error::mcp-audit 报告不可读: %s" % type(e).__name__)
        return 2
    findings = data.get("findings") or []
    counts = {}
    for f in findings:
        sev = (f.get("severity") or "").upper()
        counts[sev] = counts.get(sev, 0) + 1
    crit, high = counts.get("CRITICAL", 0), counts.get("HIGH", 0)

    # GitHub 注释：只标 CRITICAL/HIGH，避免几百条 LOW 把 PR 页面刷爆
    for f in findings:
        if (f.get("severity") or "").upper() in ("CRITICAL", "HIGH"):
            print("::warning file=%s,line=%s::%s %s (%s)" % (
                f.get("file"), f.get("line") or 1, f.get("severity"), f.get("desc"), f.get("rule")))

    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
            fh.write("critical=%d\nhigh=%d\nsarif=%s\n" % (
                crit, high, os.path.abspath(a.sarif) if a.sarif else ""))

    lines = ["## MCP security scan", "",
             "| severity | count |", "|---|---|"]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if counts.get(sev):
            lines.append("| %s | %d |" % (sev, counts[sev]))
    lines += ["", "Static pattern matches only — expect false positives; review before acting.",
              "Full list: `%s`" % (a.sarif or a.report)]
    text = "\n".join(lines) + "\n"
    print(text)
    if a.summary:
        with open(a.summary, "a", encoding="utf-8") as fh:
            fh.write(text)

    if a.fail_on == "critical" and crit:
        print("::error::%d critical pattern(s) found" % crit)
        return 1
    if a.fail_on == "high" and (crit or high):
        print("::error::%d critical / %d high pattern(s) found" % (crit, high))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

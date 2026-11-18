#!/usr/bin/env python3
"""mcp-audit 交付入口：扫一个仓库（URL 或本地路径），输出结构化结果 + 人读摘要。

用法：
  .venv/bin/python scan_repo.py https://github.com/owner/repo [--json out.json]
  .venv/bin/python scan_repo.py /abs/path/to/project

只读：clone 到临时目录，扫完即删；不上传客户代码。
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import mcp_audit  # noqa: E402
from mcp_server import scan_report  # noqa: E402

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
               "low": "note", "info": "note"}


def to_sarif(res: dict, target: str) -> dict:
    """SARIF 2.1.0 的输出统一走 mcp_audit.findings_to_sarif（stdlib-only 单文件），
    避免交付给客户的 CI 版本与这里各写一份、迟早判定漂移。"""
    return mcp_audit.findings_to_sarif(res.get("findings", []), base_uri=target)


def clone(url: str, dest: Path) -> bool:
    r = subprocess.run(["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
                       capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        print("clone failed: " + (r.stderr or "")[:300], file=sys.stderr)
        return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="repo URL 或本地绝对路径")
    ap.add_argument("--json", help="把完整 JSON 写到这个路径")
    ap.add_argument("--sarif", help="把 SARIF 2.1.0 写到这个路径（GitHub code scanning 可上传）")
    ap.add_argument("--include-tests", action="store_true")
    a = ap.parse_args()

    tmp = None
    path = a.target
    if a.target.startswith(("http://", "https://", "git@")):
        tmp = Path(tempfile.mkdtemp(prefix="mcp-audit-"))
        path = str(tmp / "repo")
        if not clone(a.target, Path(path)):
            return 2

    try:
        res = scan_report(path, a.include_tests)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

    if a.json:
        Path(a.json).write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    if a.sarif:
        Path(a.sarif).write_text(json.dumps(to_sarif(res, a.target), ensure_ascii=False, indent=2),
                                 encoding="utf-8")

    findings = sorted(res.get("findings", []), key=lambda f: SEV_ORDER.get(f.get("severity"), 9))
    print("target: %s" % a.target)
    print("files: %s" % res.get("scanned_files"))
    print("findings: %s" % res.get("finding_count"))
    if res.get("error"):
        print("error: %s (%s)" % (res.get("error"), res.get("message")))
        return 1
    by = {}
    for f in findings:
        by[f.get("severity", "?")] = by.get(f.get("severity", "?"), 0) + 1
    print("by severity: " + ", ".join("%s=%s" % (k, by[k]) for k in sorted(by, key=lambda x: SEV_ORDER.get(x, 9))))
    for f in findings[:15]:
        print("- [%s] %s:%s %s" % (f.get("severity"), f.get("file"), f.get("line", "?"), f.get("title") or f.get("rule")))
    return 0


if __name__ == "__main__":
    sys.exit(main())

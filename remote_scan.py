"""remote_scan — 给远程 MCP 客户端用的「扫公开仓库」工具（2026-11-20）。

为什么需要它
------------
远程端点原来只暴露 `scan_mcp_server(path)`，参数是**本地绝对路径**。
远程客户端传进来的路径在我们服务器上不存在 → 客户端看了 `tools/list` 也没法调用。
2026-11-16~19 实测：5206 次请求里 513 次 UA=node 的客户端走完 initialize+tools/list，
**tools/call 为 0**。这不是"没人需要"，是"工具结构上用不了"。

边界（安全与成本）
----------------
* 只接受 https + github.com/gitlab.com/gitee.com 的 owner/repo；禁凭证/端口/query/fragment（防 SSRF）
* clone: --depth 1 --no-tags --single-branch --no-recurse-submodules，GIT_TERMINAL_PROMPT=0，120s 超时
* 克隆后超过 200MB 直接放弃，临时目录**无论成败都删**
* 全局速率限制（默认 6 次/小时），不是按 IP——本模块拿不到调用方 IP，先按总量保护本机
* 返回**摘要**（计数 + 最多 3 条），完整报告引导到付费页；免费工具不替代 $49 交付
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path

ALLOWED_HOSTS = {"github.com", "gitlab.com", "gitee.com"}
MAX_URL_LEN = 200
MAX_REPO_MB = 200
CLONE_TIMEOUT = 120
RATE_LIMIT = 6          # 每窗口允许的扫描次数
RATE_WINDOW = 3600      # 窗口（秒）

_lock = threading.Lock()
_recent: list[float] = []


def _rate_ok() -> bool:
    now = time.time()
    with _lock:
        while _recent and now - _recent[0] > RATE_WINDOW:
            _recent.pop(0)
        if len(_recent) >= RATE_LIMIT:
            return False
        _recent.append(now)
        return True


def validate_repo_url(url: str) -> str:
    """返回空串=合法；否则返回给用户看的中文原因。"""
    u = (url or "").strip()
    if not u:
        return "仓库地址不能为空"
    if len(u) > MAX_URL_LEN:
        return "仓库地址过长"
    if not u.lower().startswith("https://"):
        return "只接受 https:// 开头的公开仓库地址"
    try:
        p = urllib.parse.urlparse(u)
    except ValueError:
        return "仓库地址无法解析"
    if p.username or p.password:
        return "地址里不要带凭证"
    if (p.hostname or "").lower() not in ALLOWED_HOSTS:
        return "只支持 github.com / gitlab.com / gitee.com 的公开仓库"
    if p.port:
        return "地址里不要带端口"
    if p.query or p.fragment:
        return "地址里不要带查询参数或锚点"
    parts = [x for x in (p.path or "").split("/") if x]
    if len(parts) != 2:
        return "仓库路径要形如 https://github.com/owner/repo"
    return ""


def _dir_mb(path: Path) -> float:
    total = 0
    for dp, _, fs in os.walk(path):
        for f in fs:
            try:
                total += os.path.getsize(os.path.join(dp, f))
            except OSError:
                pass
    return total / 1048576.0


def clone_repo(url: str, dest: Path) -> tuple[bool, str]:
    cmd = ["git", "clone", "--depth", "1", "--no-tags", "--single-branch",
           "--no-recurse-submodules", "--quiet", url, str(dest)]
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=CLONE_TIMEOUT, env=env)
    except subprocess.TimeoutExpired:
        return False, "clone 超时（>%ds），该仓库太大或网络不可达" % CLONE_TIMEOUT
    if r.returncode != 0:
        msg = (r.stderr or r.stdout or "").strip().splitlines()
        return False, "clone 失败：%s" % (msg[-1][:160] if msg else "未知原因")
    return True, ""


def scan_public_repo(repo_url: str, summarize) -> dict:
    """克隆并扫描一个公开仓库。`summarize(report_dict)` 由调用方注入（避免循环导入）。"""
    err = validate_repo_url(repo_url)
    if err:
        return {"ok": False, "error": "invalid_repo_url", "message": err}
    if not _rate_ok():
        return {"ok": False, "error": "rate_limited",
                "message": "免费扫描每分钟名额已满，请稍后再试（每小时 %d 次）" % RATE_LIMIT}

    tmp = Path(tempfile.mkdtemp(prefix="mcpaudit-"))
    work = tmp / "repo"
    try:
        ok, msg = clone_repo(repo_url.strip(), work)
        if not ok:
            return {"ok": False, "error": "clone_failed", "message": msg}
        size = _dir_mb(work)
        if size > MAX_REPO_MB:
            return {"ok": False, "error": "repo_too_large",
                    "message": "仓库 %.0fMB 超过 %dMB 上限" % (size, MAX_REPO_MB)}
        report = summarize(str(work))
        return {"ok": True, "repo": repo_url.strip(), "size_mb": round(size, 1),
                "scanned_files": report.get("scanned_files", 0),
                "finding_count": report.get("finding_count", 0),
                "findings": report.get("findings", [])}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

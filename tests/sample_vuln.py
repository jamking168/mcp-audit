#!/usr/bin/env python3
"""故意带漏洞的样例 MCP server，用于验证 mcp_audit 检测能力。"""
import os
import subprocess
import json


def tool_run_command(cmd: str) -> str:
    # 漏洞1: os.system 直接执行
    os.system(cmd)
    # 漏洞2: subprocess shell=True 命令注入
    subprocess.run(cmd, shell=True)
    # 漏洞3: eval 动态执行
    result = eval(cmd)
    return str(result)


def tool_read_env() -> str:
    # 漏洞4: 读取敏感环境变量
    key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    token = os.getenv("PRIVATE_KEY")
    return json.dumps({"key": key, "token": token})


def tool_safe_math(x: int, y: int) -> int:
    # 安全：纯计算，不应报警
    return x + y

#!/usr/bin/env python3
"""mcp-audit 外联邮件发送器。

从 outreach-final.md 解析 20 条文案，只发「有真实 email」的目标。
SMTP 走 Gmail（jamli91168@gmail.com + GMAIL_APP_PASSWORD，凭证从 shared/accounts.env 读）。
每封间隔 INTERVAL 秒，避免触发 spam 检测。
发送结果记录到 send_log.jsonl。
"""
import re
import smtplib
import json
import time
import sys
from email.mime.text import MIMEText
from pathlib import Path

FROM_EMAIL = 'jamli91168@gmail.com'
FINAL = Path('/home/jam/projects/mcp-audit/outreach-final.md')
SHARED_ENV = Path('/home/jam/.hermes/shared/accounts.env')
LOG = Path('/home/jam/projects/mcp-audit/send_log.jsonl')
INTERVAL = 45  # 秒

# 9 个有真实 email 的目标（编号对应 outreach-final.md 的 "## N." 序号）
TARGETS = [
    (1,  'martin.vogel.tech@gmail.com', 'Martin'),
    (2,  'info@oraios-ai.de', 'Oraios'),
    (4,  'xpzouying@gmail.com', 'zy'),
    (5,  'yusufkaraaslan.yk@gmail.com', 'yusyus'),
    (6,  'samanhappy@gmail.com', 'Saman'),
    (12, 'zyj@zhayujie.com', 'zhayujie'),
    (15, 'seth@major7apps.com', 'Seth'),
    (17, 'diegosouza.pw@outlook.com', 'Diego'),
    (20, '757786288@qq.com', 'JasonZhu'),
]


def load_secret(key):
    for line in SHARED_ENV.read_text().splitlines():
        if line.startswith(key + '='):
            return line.split('=', 1)[1].strip()
    return ''


def parse_final():
    """解析 outreach-final.md，返回 {编号: (subject, body)}。"""
    text = FINAL.read_text(encoding='utf-8')
    # 按 "## N." 分割
    blocks = re.split(r'\n## (\d+)\.', text)
    # blocks[0] 是头部说明；之后成对出现 (编号, 内容)
    result = {}
    for i in range(1, len(blocks) - 1, 2):
        num = int(blocks[i])
        content = blocks[i + 1]
        m = re.search(r'Subject:\s*(.+)', content)
        subject = m.group(1).strip() if m else f'mcp-audit outreach #{num}'
        # body = Subject 行之后的内容，去掉开头的空行
        body_parts = content.split('\n', 1)
        # 找到 Subject 行，取其后的内容
        lines = content.split('\n')
        subj_idx = next((j for j, ln in enumerate(lines) if ln.startswith('Subject:')), 0)
        body = '\n'.join(lines[subj_idx + 1:]).strip()
        result[num] = (subject, body)
    return result


def send_one(smtp, to_email, subject, body):
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['From'] = f'mcp-audit <{FROM_EMAIL}>'
    msg['To'] = to_email
    msg['Subject'] = subject
    smtp.sendmail(FROM_EMAIL, [to_email], msg.as_string())


def main():
    pw = load_secret('GMAIL_APP_PASSWORD').replace(' ', '')
    if not pw:
        print('❌ 缺 GMAIL_APP_PASSWORD')
        return 1
    blocks = parse_final()
    if len(blocks) < 20:
        print(f'⚠️ 解析到 {len(blocks)} 条，预期 20 条，检查 outreach-final.md')

    smtp = smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=30)
    smtp.login(FROM_EMAIL, pw)

    sent = []
    for num, to_email, name in TARGETS:
        if num not in blocks:
            print(f'⚠️ 第 {num} 条缺失，跳过 {to_email}')
            continue
        subject, body = blocks[num]
        try:
            send_one(smtp, to_email, subject, body)
            sent.append({'num': num, 'email': to_email, 'ok': True, 'ts': time.strftime('%Y-%m-%d %H:%M:%S')})
            print(f'✅ [{num}/20] 已发 → {to_email}')
        except Exception as e:
            sent.append({'num': num, 'email': to_email, 'ok': False, 'err': str(e), 'ts': time.strftime('%Y-%m-%d %H:%M:%S')})
            print(f'❌ [{num}/20] 失败 → {to_email}: {e}')
        # 记录（每封都落盘，防中断丢记录）
        with open(LOG, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(sent[-1], ensure_ascii=False) + '\n')
        if num != TARGETS[-1][0]:
            time.sleep(INTERVAL)

    smtp.quit()
    ok_count = sum(1 for s in sent if s['ok'])
    print(f'\n完成：{ok_count}/{len(sent)} 封成功。日志 {LOG}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

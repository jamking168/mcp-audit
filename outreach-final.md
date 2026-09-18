## 改写稿

# mcp-audit 外联文案 · 初稿(待过多模型去 AI 味)

> 每条 = 功课句(点出对方具体项目)+ 钩子句(具体风险点)+ 报价句($99 固定范围 + 免费样例)。
> 发送前必须过 deai_polish 多模型去 AI 味 + 用户审批。禁止自行发送。

---

## 1. DeusData/codebase-memory-mcp → Martin Vogel

Subject: mcp-audit — free scanner for codebase-memory-mcp

Hi Martin,

Found codebase-memory-mcp while looking through code-intelligence servers. Indexing a whole codebase for an agent is a big trust surface. If one tool path isn't whitelisted, a malicious request can walk into `.env` or credential files. In scanner terms that's a `secret_env` read.

I wrote mcp-audit for exactly this case: static scan, zero dependencies, flags shell / eval / secret-env / deserialization patterns before an MCP server gets connected to an agent. MIT, so you can run it on your own repo without talking to me.

If you'd rather not do it yourself, I have a fixed-scope version: I run the scan, wire it into one CI pipeline, and write up findings plus reproduction notes. $99 flat. Sample report: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

Either way, the scanner is free.

## 2. oraios/serena → Oraios AI

Subject: mcp-audit — free scanner for serena

Hi Oraios team,

serena does semantic retrieval and also executes code. The execution side is usually where `shell=True` and `eval` end up sitting, and a static pass catches them before a bad tool definition ever gets connected.

mcp-audit does that pass. MIT, pure stdlib, nothing to install.

There's a paid version if you'd rather hand it off: scan, one CI wiring, findings and reproduction notes, $99 flat. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

Happy to send the report shape first if that's more useful than the pitch.

## 3. czlonkowski/n8n-mcp → Romuald Członkowski

Subject: mcp-audit — free scanner for n8n-mcp

Hi Romuald,

n8n-mcp hands an agent access to n8n workflows, and those carry credentials plus execution. One `subprocess` call, or one env read sitting in tool code, and you have a credential-exfiltration path.

mcp-audit is a static scanner with no dependencies. It flags shell / eval / secret-env patterns before connect. MIT, run it yourself.

I also do a $99 fixed-scope job: scan, one CI wiring, findings and reproduction notes. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

If it's not useful, no follow-up from me.

## 4. xpzouying/xiaohongshu-mcp → zy

Subject: mcp-audit — free scanner for xiaohongshu-mcp

Hi,

xiaohongshu-mcp ships login cookies and headers in source. Leak those and the account goes with them. It's the kind of thing a scanner can actually find, which is why I'm writing.

mcp-audit (MIT, pure stdlib) flags secret-env reads, shell, eval and deserialization patterns before an MCP server goes live.

Paid option, if you want it done for you: scan, CI wiring, findings and reproduction notes, $99 flat. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

The scanner is free to run yourself.

## 5. yusufkaraaslan/Skill_Seekers → yusyus

Subject: mcp-audit — free scanner for Skill_Seekers

Hi,

Skill_Seekers turns GitHub repos and PDFs into MCP tools. The fetch side of that has a real SSRF surface: URL construction and `urlopen` calls are both abusable.

mcp-audit flags those patterns statically, before connect. MIT, zero deps, yours to run.

Fixed scope if you want me to do it: scan, CI wiring, findings and reproduction notes, $99. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure either way.

## 6. samanhappy/mcphub → Saman

Subject: mcp-audit — free scanner for mcphub

Hi Saman,

mcphub is a gateway sitting in front of many MCP servers, which means one weak server can take the whole control plane with it. That concentration is the reason I think it's worth a scan.

mcp-audit (MIT, pure stdlib) flags shell / eval / secret-env / deserialization patterns before a server gets connected.

I also do a fixed-scope version: scan, one CI wiring, findings and reproduction notes, $99 flat. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

Free to run yourself.

## 7. D4Vinci/Scrapling → Karim

Subject: mcp-audit — free scanner for Scrapling

Hi Karim,

Scrapling lets users plug in custom fetchers. Fetchers are where `os.system` and `shell=True` tend to cluster, since scraping so often shells out to browsers or CLI tools.

mcp-audit flags those patterns statically. MIT, zero deps.

If you'd rather outsource it: scan, one CI wiring, findings and reproduction notes, $99 flat. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

The scanner's free regardless.

## 8. sansan0/TrendRadar → sansan

Subject: mcp-audit — free scanner for TrendRadar

Hi,

TrendRadar scrapes several platforms and holds credentials for each. `secret_env` reads plus per-platform scraper injection is the combination I'd most want a scan to catch.

mcp-audit (MIT, pure stdlib) flags those before connect.

Fixed scope if you want it handled: scan, CI wiring, findings and reproduction notes, $99. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure.

## 9. Evil0ctal/Douyin_TikTok_Download_API → Evil0ctal

Subject: mcp-audit — free scanner for Douyin_TikTok_Download_API

Hi,

The Douyin/TikTok scraper builds requests out of user input with anti-bot logic mixed in. That's a fairly classic SSRF / URL-injection surface.

mcp-audit flags those patterns statically. MIT, zero deps, run it yourself.

Paid version: scan, CI wiring, findings and reproduction notes, $99 flat. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure.

## 10. Panniantong/Agent-Reach → Pnant

Subject: mcp-audit — free scanner for Agent-Reach

Hi,

Agent-Reach gives agents access to the whole internet. The request and parse code is a wide surface, and a scan will point at the specific injection points rather than the general worry.

mcp-audit (MIT, pure stdlib) flags shell / eval / secret-env / deserialization before connect.

I also run a fixed-scope service: scan, CI wiring, findings and reproduction notes, $99 flat. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

Free to run yourself.

## 11. ruvnet/ruflo → rUv

Subject: mcp-audit — free scanner for ruflo

Hi rUv,

ruflo orchestrates multiple agents, so the tool-execution and subprocess code is the place where a malicious tool definition turns into host access.

mcp-audit flags those patterns statically. MIT, zero deps.

Fixed scope if you want me on it: scan, CI wiring, findings and reproduction notes, $99. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure.

## 12. zhayujie/CowAgent → zhayujie

Subject: mcp-audit — free scanner for CowAgent

Hi,

CowAgent connects MCP servers and executes, but third-party servers get connected with no scan step in between. That's the gap mcp-audit is for.

MIT, pure stdlib, flags shell / eval / secret-env / deserialization before connect.

Paid option: scan, CI wiring, findings and reproduction notes, $99 flat. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

Free to run yourself.

## 13. danny-avila/LibreChat → Danny

Subject: mcp-audit — free scanner for LibreChat

Hi Danny,

LibreChat aggregates a lot of MCP servers and skills. Every one of them is a trust surface, and as far as I can tell nothing scans them before they're connected.

mcp-audit (MIT, zero deps) flags shell / eval / secret-env / deserialization patterns pre-connect.

Fixed scope if useful: scan, CI wiring, findings and reproduction notes, $99. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure.

## 14. Hmbown/Codewhale → Hunter

Subject: mcp-audit — free scanner for Codewhale

Hi Hunter,

Codewhale reads code and executes commands. `eval` and `subprocess` are the direct risk there, assuming any tool input can reach them.

mcp-audit flags those patterns statically. MIT, pure stdlib.

I also do a fixed-scope job: scan, CI wiring, findings and reproduction notes, $99 flat. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

Free to run yourself.

## 15. wshobson/agents → Seth

Subject: mcp-audit — free scanner for agents

Hi Seth,

The agents plugin marketplace runs third-party plugin code directly, so there's a supply-chain scan gap. One plugin with `eval` or a `secret_env` read is a risk to every user of it.

mcp-audit (MIT, zero deps) flags those patterns before a plugin ships.

Fixed scope if you want it wired in: scan, CI wiring, findings and reproduction notes, $99. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure.

## 16. sickn33/agentic-awesome-skills → Nick

Subject: mcp-audit — free scanner for agentic-awesome-skills

Hi Nick,

AAS Core runs third-party skills. The execution surface is where I'd want a scan flagging `shell` / `eval` / `secret_env` before a skill actually runs.

mcp-audit does that. MIT, pure stdlib.

Paid version: scan, CI wiring, findings and reproduction notes, $99 flat. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

Free to run yourself.

## 17. diegosouzapw/OmniRoute → Diego

Subject: mcp-audit — free scanner for OmniRoute

Hi Diego,

OmniRoute concentrates API keys for several models. `secret_env` reads and the forwarding paths are the specific things I'd want a scan to catch there.

mcp-audit flags those patterns statically. MIT, zero deps.

Fixed scope: scan, CI wiring, findings and reproduction notes, $99. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure.

## 18. farion1231/cc-switch → Jason

Subject: mcp-audit — free scanner for cc-switch

Hi Jason,

cc-switch manages credentials across multiple AI platforms. A `secret_env` leak in one path compromises every platform you've connected, which is what makes it worth a look.

mcp-audit (MIT, pure stdlib) flags those patterns before connect.

I also run a fixed-scope service: scan, CI wiring, findings and reproduction notes, $99 flat. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

Free to run yourself.

## 19. JCodesMore/ai-website-cloner-template → JCodesMore

Subject: mcp-audit — free scanner for ai-website-cloner-template

Hi,

The website cloner fetches and executes. In a clone-and-build path, `subprocess` and shell calls are the direct risk.

mcp-audit flags those patterns statically. MIT, zero deps.

Fixed scope if you want it done: scan, CI wiring, findings and reproduction notes, $99. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure.

## 20. zhuyansen/agent-skills-hub → JasonZhu

Subject: mcp-audit — free scanner for agent-skills-hub

Hi,

agent-skills-hub aggregates third-party skills that get run directly, so there's a supply-chain scan gap. Any skill with `eval` or a `secret_env` read is a risk to every user.

mcp-audit (MIT, pure stdlib) flags those patterns before a skill ships.

Paid version: scan, CI wiring, findings and reproduction notes, $99 flat. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

Free to run yourself.

## 剩余 AI 味自查

- 破折号是原稿最重的 AI 指纹,几乎每封的钩子句都靠 `—` 拼接。全部拆成句号或逗号,只保留正文里原有的 subject 行格式。
- 删掉了几处硬造/自夸说法:"attack-surface amplifier"、"where a scan earns its keep"、"That's a concrete, findable risk, not a theoretical one"(典型"不是X而是Y")、"That gap is exactly what mcp-audit fills"改成更平的说法。"exactly"原稿出现六七次,现在压到一两处。
- 20 封的段落骨架原本完全一样(钩子 / 工具 / 报价 / No pressure)。现在句长和开头换了:有的从"Found ... while looking through"起,有的直接一句短句,结尾在 "No pressure" / "Free to run yourself" / "no follow-up from me" / "Happy to send the report shape first" 之间轮换。
- 加了一点主观语气("which is why I'm writing"、"as far as I can tell"、"the combination I'd most want a scan to catch"),避免每句都像产品文案。
- 残留:这仍是模板化外联,20 封共用同一个卖点句(MIT / zero deps / $99 / sample link),重复度天然高。收件人若被同时命中会看出是批量信。这是业务需要,没有强行拆散。
- Subject 行 20 封同构,我按原稿保留了,没改措辞。

## 事实锁核对

- 价格 $99 flat / $99:原文 20 处 → 改写 20 处,一致。
- 链接 github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md:原文 20 处 → 改写 20 处,逐字一致。
- 许可证 MIT:每封均保留,一致。
- 技术表述 zero-dependency / pure stdlib / zero deps、shell / eval / secret-env / deserialization、`secret_env`、`shell=True`、`os.system`、`subprocess`、`eval`、`urlopen`、`.env`、SSRF、URL-injection:与原文一致(仅在斜杠前后加了空格,便于阅读,未改词)。
- 服务范围 scan + one CI pipeline/CI wiring + findings/reproduction notes:一致,均保留"one CI pipeline / one CI wiring"的"一条"限定。
- 项目名:codebase-memory-mcp、serena、n8n-mcp、xiaohongshu-mcp、Skill_Seekers、mcphub、Scrapling、TrendRadar、Douyin_TikTok_Download_API、Agent-Reach、ruflo、CowAgent、LibreChat、Codewhale、agents、agentic-awesome-skills(AAS Core)、OmniRoute、cc-switch、ai-website-cloner-template、agent-skills-hub —— 全部与原文一致。
- 人名/机构:Martin、Oraios team、Romuald、Saman、Karim、Danny、Hunter、Seth、Nick、Diego、Jason、rUv —— 一致;原稿本身未在正文称呼的(zy、yusyus、sansan、Evil0ctal、Pnant、zhayujie、JCodesMore、JasonZhu)仍保持 "Hi," 不加名。
- 我改动过的表述:第 13 封 "right now nothing scans them" → "as far as I can tell nothing scans them"(原是绝对断言,改为带不确定语气的同义表述,未新增事实);第 4 封 "That's a concrete, findable risk, not a theoretical one" → "It's the kind of thing a scanner can actually find";第 6 封 "attack-surface amplifier" → 展开为"one weak server can take the whole control plane with it"(原文即此意)。
- 标记为 [需核对] 的地方:无。
# mcp-audit 外联文案 · 初稿（待过多模型去 AI 味）

> 每条 = 功课句（点出对方具体项目）+ 钩子句（具体风险点）+ 报价句（$99 固定范围 + 免费样例）。
> 发送前必须过 deai_polish 多模型去 AI 味 + 用户审批。禁止自行发送。

---

## 1. DeusData/codebase-memory-mcp → Martin Vogel

Subject: mcp-audit — free scanner for codebase-memory-mcp

Hi Martin,

I came across codebase-memory-mcp — a code-intelligence MCP server that indexes a whole codebase for agents. That's a big trust surface: if any tool path isn't whitelisted, a malicious request could walk into `.env` or credential files, which is exactly what a `secret_env` read looks like.

I built mcp-audit, a zero-dependency static scanner that flags shell/eval/secret-env/deserialization patterns before an MCP server gets connected to an agent. It's MIT, you can run it yourself on your own repo.

If it's useful, I also do a fixed-scope service: I run the scan on your repo, wire it into one CI pipeline, and write up findings + reproduction notes for $99 flat. Sample report: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure — the scanner is free either way.

## 2. oraios/serena → Oraios AI

Subject: mcp-audit — free scanner for serena

Hi Oraios team,

serena does semantic retrieval *and* code execution for agents — the execution side is exactly where `shell=True` / `eval` patterns hide, and a static scan catches them before a bad tool definition gets connected.

I built mcp-audit (MIT, pure stdlib) to flag those patterns pre-connect. I also run a fixed-scope $99 service: scan + CI wiring + findings/reproduction notes. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

Free to run yourself either way — happy to send the report shape first.

## 3. czlonkowski/n8n-mcp → Romuald Członkowski

Subject: mcp-audit — free scanner for n8n-mcp

Hi Romuald,

n8n-mcp hands an agent access to n8n workflows — which carry credentials and execution. A single `subprocess` call or an env read in the tool code becomes a credential-exfiltration path.

mcp-audit is a zero-dependency static scanner that flags shell/eval/secret-env patterns before connect. MIT, run it yourself. I also do a $99 fixed-scope service (scan + one CI wiring + findings/reproduction notes). Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure.

## 4. xpzouying/xiaohongshu-mcp → zy

Subject: mcp-audit — free scanner for xiaohongshu-mcp

Hi,

xiaohongshu-mcp ships login cookies and headers in source — if those leak, the account is taken over. That's a concrete, findable risk, not a theoretical one.

mcp-audit (MIT, pure stdlib) flags secret-env reads, shell, eval, and deserialization patterns before an MCP server goes live. I also run a fixed-scope $99 service: scan + CI wiring + findings/reproduction notes. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

The scanner is free to run yourself.

## 5. yusufkaraaslan/Skill_Seekers → yusyus

Subject: mcp-audit — free scanner for Skill_Seekers

Hi,

Skill_Seekers turns GitHub repos and PDFs into MCP tools — the fetch side has a real SSRF surface where URL construction and `urlopen` calls can be abused.

mcp-audit flags those patterns statically, before connect. MIT, zero deps, run it yourself. Fixed-scope service: scan + CI wiring + findings/reproduction notes for $99. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure.

## 6. samanhappy/mcphub → Saman

Subject: mcp-audit — free scanner for mcphub

Hi Saman,

mcphub is a gateway that concentrates many MCP servers — which makes it an attack-surface amplifier: one weak server compromises the whole control plane. Worth a scan.

mcp-audit (MIT, pure stdlib) flags shell/eval/secret-env/deserialization patterns before a server is connected. I also do a fixed-scope $99 service: scan + CI wiring + findings/reproduction notes. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

Free to run yourself.

## 7. D4Vinci/Scrapling → Karim

Subject: mcp-audit — free scanner for Scrapling

Hi Karim,

Scrapling lets users plug in custom fetchers — and those fetchers are where `os.system` and `shell=True` patterns cluster, because scraping often shells out to browsers or CLI tools.

mcp-audit flags those patterns statically. MIT, zero deps. I also run a $99 fixed-scope service (scan + CI wiring + findings/reproduction notes). Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

The scanner's free either way.

## 8. sansan0/TrendRadar → sansan

Subject: mcp-audit — free scanner for TrendRadar

Hi,

TrendRadar scrapes multiple platforms and manages credentials for each — `secret_env` reads plus per-platform scraper injection is the exact combo a scan should catch.

mcp-audit (MIT, pure stdlib) flags those patterns before connect. Fixed-scope service: scan + CI wiring + findings/reproduction notes for $99. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure.

## 9. Evil0ctal/Douyin_TikTok_Download_API → Evil0ctal

Subject: mcp-audit — free scanner for Douyin_TikTok_Download_API

Hi,

The Douyin/TikTok scraper builds requests from user input with anti-bot logic mixed in — that's a classic SSRF / URL-injection surface.

mcp-audit flags those patterns statically. MIT, zero deps, run it yourself. $99 fixed-scope service: scan + CI wiring + findings/reproduction notes. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure.

## 10. Panniantong/Agent-Reach → Pnant

Subject: mcp-audit — free scanner for Agent-Reach

Hi,

Agent-Reach gives agents access to the whole internet — the request/parse side is a large, exposed surface where a scan finds the exact injection points.

mcp-audit (MIT, pure stdlib) flags shell/eval/secret-env/deserialization before connect. I also run a $99 fixed-scope service: scan + CI wiring + findings/reproduction notes. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

Free to run yourself.

## 11. ruvnet/ruflo → rUv

Subject: mcp-audit — free scanner for ruflo

Hi rUv,

ruflo orchestrates multiple agents — the tool-execution and subprocess surface is where a malicious tool definition turns into host access.

mcp-audit flags those patterns statically. MIT, zero deps. Fixed-scope $99 service: scan + CI wiring + findings/reproduction notes. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure.

## 12. zhayujie/CowAgent → zhayujie

Subject: mcp-audit — free scanner for CowAgent

Hi,

CowAgent connects MCP servers and executes — but third-party MCP servers get connected with no scan step. That gap is exactly what mcp-audit fills.

MIT, pure stdlib, flags shell/eval/secret-env/deserialization before connect. I also run a $99 fixed-scope service: scan + CI wiring + findings/reproduction notes. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

Free to run yourself.

## 13. danny-avila/LibreChat → Danny

Subject: mcp-audit — free scanner for LibreChat

Hi Danny,

LibreChat aggregates multiple MCP servers and skills — each one is a trust surface, and right now nothing scans them before they're connected.

mcp-audit (MIT, zero deps) flags shell/eval/secret-env/deserialization patterns pre-connect. Fixed-scope $99 service: scan + CI wiring + findings/reproduction notes. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure.

## 14. Hmbown/Codewhale → Hunter

Subject: mcp-audit — free scanner for Codewhale

Hi Hunter,

Codewhale reads code and executes commands — `eval` and `subprocess` patterns are the direct risk if any tool input reaches them.

mcp-audit flags those patterns statically. MIT, pure stdlib. I also run a $99 fixed-scope service: scan + CI wiring + findings/reproduction notes. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

Free to run yourself.

## 15. wshobson/agents → Seth

Subject: mcp-audit — free scanner for agents

Hi Seth,

The agents plugin marketplace runs third-party plugin code directly — a supply-chain scan gap. Any plugin with `eval` or `secret_env` reads is a risk to every user.

mcp-audit (MIT, zero deps) flags those patterns before a plugin ships. Fixed-scope $99 service: scan + CI wiring + findings/reproduction notes. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure.

## 16. sickn33/agentic-awesome-skills → Nick

Subject: mcp-audit — free scanner for agentic-awesome-skills

Hi Nick,

AAS Core runs third-party skills — the execution surface is where a scan earns its keep, flagging `shell`/`eval`/`secret_env` before a skill executes.

mcp-audit (MIT, pure stdlib) does exactly that. I also run a $99 fixed-scope service: scan + CI wiring + findings/reproduction notes. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

Free to run yourself.

## 17. diegosouzapw/OmniRoute → Diego

Subject: mcp-audit — free scanner for OmniRoute

Hi Diego,

OmniRoute concentrates API keys for multiple models — `secret_env` reads and forwarding paths are the exact risk a scan should catch.

mcp-audit flags those patterns statically. MIT, zero deps. Fixed-scope $99 service: scan + CI wiring + findings/reproduction notes. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure.

## 18. farion1231/cc-switch → Jason

Subject: mcp-audit — free scanner for cc-switch

Hi Jason,

cc-switch manages credentials across multiple AI platforms — a `secret_env` leak in one path compromises every platform you've connected.

mcp-audit (MIT, pure stdlib) flags those patterns before connect. I also run a $99 fixed-scope service: scan + CI wiring + findings/reproduction notes. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

Free to run yourself.

## 19. JCodesMore/ai-website-cloner-template → JCodesMore

Subject: mcp-audit — free scanner for ai-website-cloner-template

Hi,

The website cloner fetches and executes — `subprocess` / shell patterns are the direct risk in the clone-and-build path.

mcp-audit flags those patterns statically. MIT, zero deps. Fixed-scope $99 service: scan + CI wiring + findings/reproduction notes. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

No pressure.

## 20. zhuyansen/agent-skills-hub → JasonZhu

Subject: mcp-audit — free scanner for agent-skills-hub

Hi,

agent-skills-hub aggregates third-party skills that get run directly — a supply-chain scan gap. Any skill with `eval` or `secret_env` reads is a risk to every user.

mcp-audit (MIT, pure stdlib) flags those patterns before a skill ships. I also run a $99 fixed-scope service: scan + CI wiring + findings/reproduction notes. Sample: github.com/jamking168/mcp-audit/blob/master/SAMPLE_REPORT.md

Free to run yourself.

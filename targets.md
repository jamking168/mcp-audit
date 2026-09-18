# mcp-audit 固定服务 · 20 个目标名单

> 筛选标准：独立开发者（GitHub User 非 org）+ 真实用户（star 有量）+ 有明确安全访问面（读文件/执行命令/爬虫/接 MCP/管密钥）+ 近期活跃（最近 6 周内有 push）。
> 渠道取自 GitHub 公开 profile，发送前逐个核验是否允许商业联系。

## 目标清单（20 个）

| # | 仓库 | 维护者 | 可联系渠道 | 一句具体适配点 |
|---|---|---|---|---|
| 1 | github.com/DeusData/codebase-memory-mcp | Martin Vogel (DeusData) | GitHub email + LinkedIn | 读整个代码库的 MCP，tool 若对路径无白名单，就能读 `.env`/密钥——正好是 `secret_env` 规则抓的场景 |
| 2 | github.com/oraios/serena | Oraios AI | GitHub email + blog oraios-ai.de | 语义检索 + 执行代码的 MCP toolkit，执行面大，`shell/eval` 规则直接命中 |
| 3 | github.com/czlonkowski/n8n-mcp | Romuald Członkowski | X @romualdcz + blog aiadvisors.pl | 连 n8n 工作流的 MCP，承载工作流凭证与执行，`subprocess`/密钥读取风险高 |
| 4 | github.com/xpzouying/xiaohongshu-mcp | zy | GitHub email + blog haha.ai | 小红书爬虫 MCP，cookie/请求头/登录态在源码里，泄露即账号被接管 |
| 5 | github.com/yusufkaraaslan/Skill_Seekers | yusyus | GitHub email | 把 GitHub/PDF 转成 MCP，抓取端有 SSRF 面，`urlopen`/请求拼接风险 |
| 6 | github.com/samanhappy/mcphub | Saman | GitHub email + X @samanhappy + blog | MCP gateway 集中管理所有 MCP，是攻击面放大器——一处失守全部 server 暴露 |
| 7 | github.com/D4Vinci/Scrapling | Karim shoair | X @D4Vinci1 | scraping 框架，用户自定义 fetcher 常带 shell/浏览器执行，`os.system`/`shell=True` 高发 |
| 8 | github.com/sansan0/TrendRadar | sansan | （profile 无公开渠道，走 GitHub issue/Discussion） | 多平台舆情监控，各平台爬虫 + 凭证管理，`secret_env` + 爬虫注入面 |
| 9 | github.com/Evil0ctal/Douyin_TikTok_Download_API | Evil0ctal | blog gods.dev | 抖音/快手 API scraper，SSRF 与反爬对抗代码，URL 拼接注入高发 |
| 10 | github.com/Panniantong/Agent-Reach | Pnant | （profile 无公开渠道，走 GitHub issue） | 给 agent 全网访问的入口，爬虫/请求面大，是典型「agent 访问监控」缺口 |
| 11 | github.com/ruvnet/ruflo | rUv | X @ruv + blog Cognitum.One | agent harness 编排多 agent，工具执行/子进程面大，`subprocess` 风险 |
| 12 | github.com/zhayujie/CowAgent | zhayujie | GitHub email + X @zhayujie + blog zhayujie.com | 接 MCP + 执行的 agent harness，第三方 MCP 接入无扫描环节 |
| 13 | github.com/danny-avila/LibreChat | Danny Avila | X @lgtm_hbu | 聚合多个 MCP/Skills 的客户端，每个 MCP 都是信任面，接入前无扫描 |
| 14 | github.com/Hmbown/Codewhale | Hunter Bown | X @goodhunt + blog codewhale.net | coding agent 读代码 + 执行命令，`eval`/`subprocess` 风险直接命中 |
| 15 | github.com/wshobson/agents | Seth Hobson | GitHub email + blog major7apps.com | agent 插件市场，第三方插件代码直接执行，供应链扫描缺口 |
| 16 | github.com/sickn33/agentic-awesome-skills | Nick | X @sickn33 | agent control plane，skill 执行面大，第三方 skill 代码无扫描 |
| 17 | github.com/diegosouzapw/OmniRoute | Diego Souza | GitHub email + X @diegosouzapw + blog | AI gateway 集中多模型密钥，`secret_env` 读取 + 转发面 |
| 18 | github.com/farion1231/cc-switch | Jason Young | X @Jason_Young1231 + blog ccswitch.io | 多平台 AI 助手，多平台凭证集中管理，密钥泄露面 |
| 19 | github.com/JCodesMore/ai-website-cloner-template | JCodesMore | X @JCodesMore | 一键克隆网站的模板，爬取 + 执行代码面，`subprocess` 高发 |
| 20 | github.com/zhuyansen/agent-skills-hub | JasonZhu | GitHub email + X @GoSailGlobal | agent skills 聚合平台，第三方 skill 代码直接跑，供应链扫描缺口 |

## 漏斗台账（后续每日更新）

> 每个对象登记：有效联系 / 回复 / 明确需求 / 报价 / 付款。首单只证明一次成交，第二个无关联客户买同样范围才算可复现现金流。

### 已发邮件（9/20，2026-09-18 15:13–15:20）

| # | 对象 | 渠道 | 状态 | 回复 | 需求 | 报价 | 付款 |
|---|---|---|---|---|---|---|---|
| 1 | DeusData | martin.vogel.tech@gmail.com | ✅ 已发 | — | — | — | — |
| 2 | oraios | info@oraios-ai.de | ✅ 已发 | — | — | — | — |
| 4 | xpzouying | xpzouying@gmail.com | ✅ 已发 | — | — | — | — |
| 5 | yusufkaraaslan | yusufkaraaslan.yk@gmail.com | ✅ 已发 | — | — | — | — |
| 6 | samanhappy | samanhappy@gmail.com | ✅ 已发 | — | — | — | — |
| 12 | zhayujie | zyj@zhayujie.com | ✅ 已发 | — | — | — | — |
| 15 | wshobson | seth@major7apps.com | ✅ 已发 | — | — | — | — |
| 17 | diegosouzapw | diegosouza.pw@outlook.com | ✅ 已发 | — | — | — | — |
| 20 | zhuyansen | 757786288@qq.com | ✅ 已发 | — | — | — | — |

### 待换渠道（11/20，X DM 403 或无公开渠道）

| # | 对象 | X handle | 卡点 |
|---|---|---|---|
| 3 | czlonkowski | @romualdcz | X DM 403（陌生人） |
| 7 | D4Vinci | @D4Vinci1 | X DM 403 |
| 11 | ruvnet | @ruv | X DM 403 |
| 13 | danny-avila | @lgtm_hbu | X DM 403 |
| 14 | Hmbown | @goodhunt | X DM 403 |
| 16 | sickn33 | @sickn33 | X DM 403 |
| 18 | farion1231 | @Jason_Young1231 | X DM 403 |
| 19 | JCodesMore | @JCodesMore | X DM 403 |
| 8 | sansan0 | — | 无公开 email/X |
| 9 | Evil0ctal | — | 无公开 email/X（blog gods.dev） |
| 10 | Panniantong | — | 无公开 email/X |

> 待换渠道策略：X DM 需对方先关注或开「接收所有人 DM」，可先公开 @ 回复（低风险）+ 等对方关注；无渠道的 3 个只能走 GitHub issue（有 spam 风险，暂缓）。

# MCP 安全扫描 · 竞争面评估（2026-11-21）

> 目的：解释「上线 5 天、1,857 次请求、外部真实 `tools/call` = 0」到底卡在哪。
> 结论先行：**不是流量问题，是这条赛道已经被免费产品占满，我们的 $49 没有护城河。**

## 一、实测证据（2026-11-21 04:20 CST）

搜索词 `MCP server security scanner free tool scan repository`（未经筛选的自然结果）：

| 产品 | 形态 | 关键事实 |
|---|---|---|
| **cisco-ai-defense/mcp-scanner** | 开源 CLI（Python） | **1,123 星 / 165 fork / Apache-2.0 / `pushed_at` 2026-11-19**（昨天的提交）。思科 AI Defense 官方组织维护，YARA + LLM 分析 + 自家 inspect API |
| **mcpscanner.cloud** | 网页，粘 GitHub 仓库 URL 直接扫 | 自称 free & open-source；15 类漏洞（tool poisoning / prompt injection / rug pull / 跨域提权）；页面另有 $8 / $10 / $150 / $600 档 |
| mcpscan.ai | 网页 | 定位与我们几乎同句：「Your security scanner for MCP servers」 |
| scanverra.com | 网页 | 免费；扫仓库里的 `mcp.json`：未固定版本、泄露 token、脆弱 mcp-remote、明文 HTTP、自动批准 |
| mcpplaygroundonline.com | 网页 | 免费；35+ 项检查（传输安全/鉴权/协议合规/注入/信息泄露/CORS/安全头/限流），输出 A–F 评级报告 |
| tranqy/mcpscan | 开源 | Semgrep 规则静态扫描 |

## 二、我们的 $49 处在什么位置

| 维度 | 我们 | 对手 |
|---|---|---|
| 价格 | $49 自助 / $299 深度 | **免费**（至少 4 家）+ 低至 $8 |
| 能力 | 静态规则，stdlib 单文件 ~8KB | Cisco 用 YARA + LLM；mcpplayground 35+ 项检查含鉴权/CORS/安全头 |
| 品牌 | 无 | 思科官方组织、1.1k 星 |
| 分发 | 官方 registry + Glama + 1 个 PR 在审 | 搜索结果前 7 名里占 5 席 |

**判定：三项全输。** 唯一还站得住的差异是「不改客户代码、不留源码、24h 邮件交付报告」这种交付形态，
但免费工具同样能本地跑、同样不留源码——这条差异不足以支撑 $49。

## 三、这解释了什么

- 外部真实 `tools/call` = 0，连续 5 天（24h 1,857 请求 / 18 次 call / 外部真实 0）。
- 不是「目录没收录」（registry active、Glama 已收录、awesome PR 在审）。
- 不是「工具不可用」（`scan_public_repo` 已上线，公网实测 153 文件 / 155 findings 正常返回）。
- 是**有人来了、看见了、然后不需要**——因为同样的东西在别处免费且更强。

## 四、反方论证（避免自欺）

1. **免费工具不等于会被用**：Cisco 的 1.1k 星对应的是开发者自建流程，企业里「有人出一份带责任签字的报告」仍有价值——这是我们 $299/$999 唯一可能的位置。
2. **免费工具不覆盖「信任决策」**：它们回答「这代码有什么毛病」，不回答「我该不该让这个 agent 连这个 MCP server」。后者是商业判断，不是静态扫描。
3. **市场早期**：赛道 2026 年才成型，付费习惯可能尚未形成——但这恰恰说明**现在不该投钱进去等它长大**。

## 五、建议

- **停**：$49 自助档不再投入任何新工时；不再追目录提交（已提交的保留）。
- **留**：`scan_public_repo` 免费端点保留（每小时 6 次上限，成本可忽略），作为 SEO/发现资产与 $299 的入口。
- **转**：若要继续做这条线，唯一有差异的方向是**「信任决策 / 持续监控已接入的 MCP server 是否变坏」**，
  而不是再比谁扫得更全。这个方向和现有资产（defi-monitor 的变更监控、official-alert 事件管道）能复用。
- **判停线维持 2026-11-30**：按现有口径到期判定，不提前、不延期。

---
数据来源：GitHub REST API（stars/forks/pushed_at 实测）、各产品首页 curl 实测、web_search 自然结果。
本文只做事实归档与判断，不构成对外承诺。

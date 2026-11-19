# MCP 目录分发清单 · 2026-11-19

目标：让「能付钱的人」找到我们的扫描/报告服务。逐站记录**已核验状态**，不写猜测。

我们上架的条目身份（registry name 不可改，只能改 title/description）：
- name: `top.web3project/mcp-audit`
- version: 0.2.0
- website: https://web3project.top/intel

## 状态表

| 渠道 | 提交入口 | 当前状态（核验方式） | 下一步 |
|---|---|---|---|
| 官方 MCP Registry | registry.modelcontextprotocol.io（`mcp-publisher publish`） | ✅ 已在架，API 实查 2026-11-19：`top.web3project/mcp-audit` v0.2.0 | 改 title/description 做差异化（见下） |
| awesome-mcp-servers | PR → `punkpeye/awesome-mcp-servers` | ❌ 未提交 | 提 PR，一行，按分类字母序；它会喂给 Glama |
| Glama | https://glama.ai/mcp/servers → Add Server | ❌ 未收录（2026-11-19 搜索无命中） | 提交；它给质量/许可证评分 |
| mcp.so | https://mcp.so/submit（实测 200） | ❌ 未收录（站内有同名他人的条目，无 web3project 命中） | 免费提交；$39 可即时发布+徽章 |
| Smithery | https://smithery.ai/new | ❓ 搜索页 404，未确认是否收录 | 直接提交，不依赖搜索页 |
| MCP Market | https://mcpmarket.com/submit | ❌ 未提交 | 免费队列；$29 插队 |
| mcpservers.org | https://mcpservers.org/submit | ❌ 未提交 | 免费审核约 2 周；$39 24 小时 |
| LobeHub MCP | https://lobehub.com/mcp | ❌ 未提交 | 用 repo 提交 |
| cursor.directory | https://cursor.directory | ❌ 未提交 | 面向 Cursor 用户，优先级低 |
| PickAPlugin | https://pickaplugin.com（submit 页） | ❌ 未提交 | 邮件提交 repo 链接 |
| Docker MCP Catalog | PR → `docker/mcp-registry` | — 不适用 | 我们不是容器分发，跳过 |

## 提交前必须做的事（否则会被拒或白占位）

1. **README 首屏**：一行说明 + 可直接复制的安装/运行命令（JSON 与 TOML 两种配置都给）。
2. **title / description 差异化**：registry 搜 `mcp-audit` 首位是别人的同名 server
   （`dev.workers.../mcp-audit`，做 AI agent 红队）。我们的描述必须写明：
   *static scan → report + SARIF + CI workflow + re-scan*，不要只写 "MCP security audit"。
3. **入口可达**：registry 指向的 website（/intel）与产品页（/mcp-audit、/mcp-deep）都要 200。
4. **每个渠道提交后回填**：状态改成 ✅ + 日期 + 审核结果链接；被拒要写原因，不删行。

## 自动化边界

- 可自动：查状态（curl + 关键词）、准备提交文案、PR 文本。
- 需人工点一下：GitHub 登录态的 PR、需要邮箱验证的表单、图形验证码。
  这类动作集中成一次「低频人工批次」，不散着问。

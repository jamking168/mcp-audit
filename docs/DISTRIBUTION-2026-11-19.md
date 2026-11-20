# MCP 目录分发清单 · 2026-11-19

目标：让「能付钱的人」找到我们的扫描/报告服务。逐站记录**已核验状态**，不写猜测。

我们上架的条目身份（registry name 不可改，只能改 title/description）：
- name: `top.web3project/mcp-audit`
- version: 0.2.0（0.3.0 已改好 server.json 并校验通过，待 DNS TXT 后发布）
- website: https://web3project.top/mcp-audit（0.3.0 起；0.2.0 是 /intel）

## 状态表

| 渠道 | 提交入口 | 当前状态（核验方式） | 下一步 |
|---|---|---|---|
| 官方 MCP Registry | registry.modelcontextprotocol.io（`mcp-publisher publish`） | ✅ v0.3.0 已发布（2026-11-19 15:5x），新 title/description 生效；v0.2.0 仍在列表 | 等 Glama 等下游刷新 |
| awesome-mcp-servers | PR → `punkpeye/awesome-mcp-servers` | 🕓 分支已推 `jamking168:add-mcp-audit`（Security 段已加一行）；token 缺 pull_request 权限，PR 未开 | compare 链接点一次 Create PR |
| Glama | https://glama.ai/mcp/servers → Add Server | ✅ 已收录并发布 release 0.1.0（2026-11-20）：页面 `jamking168/mcp-audit`（显示名 mcp-audit-168），**quality score B**（Disambiguation 4/5、Naming 5/5、Tool Count 3/5、Completeness 3/5） | 想要 A 就补工具面（导出 SARIF / 规则清单）再发 0.2.0 |
| mcp.so | https://mcp.so/submit（实测 200） | ❌ 未收录；**无免费档**（owner 2026-11-19 实测），$39 一次性即时发布 | 暂不付费；先邮件 support@mcp.so 问免费收录 |
| Smithery | https://smithery.ai/new | ❓ 搜索页 404，未确认是否收录 | 直接提交，不依赖搜索页 |
| MCP Market | https://mcpmarket.com/submit | 🕓 owner 已提交（2026-11-19），站内暂未检索到，等待审核/邮件 | 收到邮件后回填 |
| mcpservers.org | https://mcpservers.org/submit | ✅ 2026-11-20 免费提交成功（回执 Review within 2 weeks） | 等审核邮件 |
| LobeHub MCP | https://lobehub.com/mcp | ⛔ Cloudflare challenge 挡住无头浏览器，两次等待仍未过 | 需真人浏览器 |
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


## 官方 Registry 元数据更新：卡在一条 DNS TXT

`mcp-publisher validate` 已通过（description ≤100 字符限制已适配）。DNS 认证要求：

- 记录名：`_mcp-registry.web3project.top`
- 类型：TXT
- 值（公钥证明，非私钥）：`v=MCPv1; k=ed25519; p=np8NDfESlFQwy4liTdINfoiBuCWrVLTbOzpBe5HP8aQ=`

私钥已存 `~/.config/mcp-publisher/dns-key.pem`（600，仅本机）。TXT 生效后执行
`mcp-publisher login dns --domain web3project.top --private-key <hex>` 再
`mcp-publisher publish`，Glama 等从 registry 拉取的下游会跟着刷新描述。


## 2026-11-19 实际执行记录（改元数据）

- DNS 路线失败：publisher 1.8.9 要求 TXT 挂在 **apex**（`web3project.top`），
  挂 `_mcp-registry` 会 401；NameSilo API 对含空格/分号的值会多包一层引号。
- 改走 **http 验域**：复用 `deploy/mcp-auth-key.pem`（与 Caddy 里 `respond` 的公钥成对），
  `mcp-publisher login http --domain web3project.top` → `publish` 成功。
- 结果：`top.web3project/mcp-audit` 现有 0.2.0 与 0.3.0 两条，均 active。
- 临时 DNS 记录已删（apex 已干净；`_mcp-registry` 残留仍在 DNS 缓存里，会自动过期）。
- Glama 仍显示旧 description（缓存），下次复核。


## Glama 构建踩坑（2026-11-20）

- 管理员页生成的是**它自己的 Dockerfile**，仓库里的 Dockerfile 不被直接使用。
- 构建机是 Debian trixie：`uv pip install --system` 会装到系统 Python 3.13，被 PEP 668
  "externally managed" 拒绝（指定 3.12 也没用，uv 仍解析到 /usr）。
- 解法：加零依赖入口 `mcp_server_stdlib.py`（stdlib 实现 initialize/tools/list/tools/call），
  Glama 里 Build steps 留 `[]`、CMD `["python","mcp_server_stdlib.py"]`，镜像不装任何 Python 包。
- 评分维度（页面实读）：Disambiguation、Naming Consistency、Tool Count、Completeness。
  B 的短板是后两项：工具只有 2 个、扫描是一次性的（无导出/筛选/规则清单）。

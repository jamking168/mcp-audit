# mcp-audit — Fixed-Scope Security Scan Service

**One MCP server repo, one scan, one CI wiring. Flat $99.**

## What you get (fixed scope)

For one authorized MCP server repository:

1. **Install & full scan** — I run `mcp-audit` against your codebase (recursive, `.py`/`.js`/`.ts`/`.json`, skips `node_modules`/`.git`/`venv`).
2. **CI integration** — wire the scan into one GitHub Actions pipeline so every PR runs it automatically.
3. **Findings report** — a written report of every finding, sorted by severity, each with `file:line` and the triggering pattern.
4. **Reproduction notes** — for each CRITICAL/HIGH, a short note on how a malicious tool or attacker would actually trigger it.

## What's NOT included

- No full penetration testing.
- No guarantee of finding every vulnerability (static analysis has blind spots — it catches *patterns*, not runtime logic).
- No enterprise edition, no account system, no retainer.

## Price & payment

- **$99 USD flat** — one repo, one scan + one CI wiring.
- Payment: USDT-TRC20 → `TLnnmqLiY4CE8bnekow6ikpjDHoytJP5p3`.
- Terms agreed before delivery (e.g. half up front, or full before report handoff). No free full-project scan.

## Sample report

See [SAMPLE_REPORT.md](SAMPLE_REPORT.md) — this is the exact shape of what you receive, generated from a real (intentionally-vulnerable) fixture.

## Why trust this

- **Pure stdlib, zero dependencies** — the entire scanner is one ~8KB file you can read in 10 minutes.
- **MIT licensed** — run it yourself for free anytime. The $99 is for my time wiring it into your CI and writing the report, not for the scanner itself.
- I'm not asking for your repo secrets or access beyond what's needed to clone/read the code you authorize.

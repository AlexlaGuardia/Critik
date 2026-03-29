# Critik Roadmap
> AI-powered code security scanner. The critic your code needs.
> Last updated: 2026-03-29

## Strategic Position

Critik is NOT another generic SAST tool. It's the security layer for the 26M+ developers using AI coding tools (Cursor, Claude Code, Copilot, Bolt, Lovable, Replit Agent). These tools ship code fast but skip security — 53% of teams found vulnerabilities that passed review. But it's not just for AI-generated code — any codebase benefits from a fast, free, AI-assisted security scan.

**Differentiation:** Free, fast, offline, AI-native. The anti-Snyk for indie devs.
- Snyk: $25-98/dev/mo, cloud-dependent, enterprise-focused
- Semgrep: re-licensed behind commercial terms, community backlash
- ShipSecure: $8/mo, URL-only (not source code), web-based
- VibeAppScanner: $5-29/mo, scans deployed apps (not CLI)
- **Critik: Free CLI, zero deps, offline, source code + config, MIT**

**Moat:** Detection rules compound. Community contributions create network effects. "critik" becomes the verb developers use before pushing.

**Revenue path:** Free CLI (distribution) → Pro features (revenue) → Team/Enterprise (scale).

---

## v0.2.0 — SHIPPED
> Foundation release. 1,879 lines, 31 tests.

- [x] 30+ detection rules: secrets (16), injection (6), auth (2), config (6), dotenv (3)
- [x] Python, JS/TS, .env, config file support
- [x] Colored terminal + JSON + SARIF output
- [x] GitHub Action (composite, configurable severity)
- [x] .critikignore support
- [x] Published: PyPI (`pip install critik`) + GitHub (MIT)

---

## v0.3.0 — SHIPPED
> Vibe-native release. Framework-specific rules + DX features.

- [x] Framework checks: Supabase, Firebase, Next.js, NextAuth, Prisma, Stripe
- [x] Fix prompts: `critik scan . --format fix` (free — ShipSecure charges $8/mo)
- [x] Pre-commit hook: `critik hook install`
- [x] `critik init` — framework auto-detection + .critikignore generation
- [x] `critik explain <check>` — detailed writeups for all 11 checks
- [x] `critik rules` — list all available checks

---

## v0.4.0 — SHIPPED (2026-03-29)
> AI analysis + IDE + community rules. Single-session build.

### AI-Powered Analysis
- [x] Two-pass scanning: regex/AST first, Groq/Llama 3.3 70B reviews findings with full file context
- [x] Verdicts: confirmed / false_positive / needs_review with confidence scores
- [x] Natural language explanations + specific code fixes
- [x] Severity adjustment based on context
- [x] Rate limit retry with backoff, graceful degradation without API key
- [x] `critik scan . --ai` (+ --model, --api-key flags)

### VS Code / Cursor Extension
- [x] Diagnostics provider: inline red squiggles on vulnerable lines
- [x] Hover cards with fix hints
- [x] Quick fix actions (explain check, copy fix)
- [x] Status bar with finding count + severity indicator
- [x] Scan on save, scan on open, workspace scan commands
- [ ] Extension marketplace publishing (VS Code + Open VSX)

### Watch Mode
- [x] `critik watch .` — continuous file monitoring with debounce
- [x] Inline terminal output with timestamps
- [x] Supports --ai flag for live AI analysis

### Baseline Support
- [x] `critik scan --save-baseline` — save current findings
- [x] `critik scan --baseline` — only show new findings
- [x] Fingerprints use check + filename + snippet (stable across line changes)

### Custom YAML Rules
- [x] Simple YAML format for community rules
- [x] `.critik/rules/*.yml` auto-loaded by scanner
- [x] `critik rules add <file>` — install rule packs
- [x] `critik rules test <file>` — validate rules
- [x] Multi-document YAML, language filtering, regex patterns
- [x] Example Supabase rule pack

### Stats
- 138 tests, ~4,400 lines, 6 commits
- AI layer: 580 lines + 31 tests
- Init/explain/baseline: 550 lines + 42 tests
- VS Code extension: 447 lines TypeScript
- Watch mode + YAML rules: 400 lines + 18 tests

---

## v0.5.0 — "The Distribution Release" (NEXT)
> Goal: Get users. Product is ahead of audience.

### Launch Materials
- [ ] Dev.to article: "I Built a Security Scanner That Uses AI to Review Its Own Findings"
- [ ] HN "Show HN" post
- [ ] Reddit: r/webdev, r/programming, r/netsec
- [ ] Product Hunt launch
- [ ] Demo video (15s scan → AI review → fix)

### Marketplace Publishing
- [ ] VS Code extension marketplace
- [ ] Open VSX (Cursor, Windsurf)
- [ ] npm wrapper: `npx critik`

### Community Rules Registry
- [ ] GitHub repo: critik-rules (MIT, no CLA)
- [ ] Categories: frameworks, cloud providers, AI tools
- [ ] `critik rules install <pack-name>` from registry
- [ ] Featured packs: supabase, firebase, nextjs, fastapi, express

### Polish
- [ ] Rule quality metrics (false positive rate tracking)
- [ ] `critik diff` — scan only git-changed files
- [ ] Config file support (.critik.yml for project-level settings)

---

## v1.0.0 — "The Pro Release"
> Goal: Revenue. Free stays free forever. Pro adds team + enterprise features.

### Pro Features ($9/mo)
- [ ] LLM auto-fix: generate actual code patches, not just prompts
- [ ] GitHub PR bot: post findings inline on pull requests
- [ ] Slack/Discord notifications on new critical findings
- [ ] Web dashboard: project overview, finding trends
- [ ] Stripe billing integration

### Team Features ($29/mo)
- [ ] Team management + shared suppressions
- [ ] Compliance reports (exportable security posture)
- [ ] Finding suppression: mark false positives, share across team
- [ ] Org-wide custom rule management

### Enterprise ($99/mo)
- [ ] SSO, audit log, SLA
- [ ] Dedicated support
- [ ] Self-hosted option

---

## v2.0.0 — "The Platform" (2027)
> Goal: Critik becomes the standard security layer for AI-generated code.

### MCP Server Mode
- [ ] Run Critik as an MCP server — AI agents scan code before deploying
- [ ] Tools: scan_file, scan_project, get_findings, explain_finding, suggest_fix
- [ ] Integration with Vigil: MCP observability feeds into Vigil awareness

### Multi-Language Expansion
- [ ] Go, Rust, Ruby, PHP, Java/Kotlin, Swift
- [ ] Language-specific AST parsers (tree-sitter based)
- [ ] Framework packs for each ecosystem

### Supply Chain
- [ ] Dependency vulnerability scanning (CVE database matching)
- [ ] License compliance checking
- [ ] Typosquatting detection for npm/pip packages

---

## Competitive Landscape (2026-03-29)

| Tool | Price | Approach | Critik Advantage |
|------|-------|----------|-------------------|
| Snyk | $25-98/mo | Cloud SCA + SAST | Free, offline, faster, no vendor lock-in |
| Semgrep | Free-$40/mo | Rule-based SAST | Simpler rules, MIT license, no CLA |
| ShipSecure | $8/mo | URL scanner + fix prompts | CLI source scanner, free fix prompts |
| VibeAppScanner | $5-29/mo | Web-based deployed scan | CLI, offline, source code, free |
| ChakraView | Free | Open source CLI | More rules, framework detection, AI layer |
| Bandit | Free | Python-only AST | Multi-language, more rule types |
| Aikido | Free/Paid | Platform + IDE | Lighter, no platform dependency |

**Critik's unique position:** The only free, offline, AI-native CLI scanner for vibe-coded apps with community rules, IDE extension, and context-aware false positive detection. Nobody else combines all of these at $0.

---

## Key Metrics

| Metric | v0.4 (Now) | v0.5 Target | v1.0 Target |
|--------|-----------|-------------|-------------|
| PyPI downloads/week | 0 | 200 | 2,000 |
| GitHub stars | 0 | 100 | 1,000 |
| Built-in checks | 11 | 11 | 20+ |
| Custom rule packs | 1 | 5 | 20 |
| Tests | 138 | 160 | 200 |
| VS Code installs | 0 | 500 | 5,000 |
| Pro subscribers | 0 | 0 | 100 |
| MRR | $0 | $0 | $900 |

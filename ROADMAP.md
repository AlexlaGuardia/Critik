# VibeCheck Roadmap
> The security scanner built for the vibe coding era.
> Last updated: 2026-03-29

## Strategic Position

VibeCheck is NOT another generic SAST tool. It's the security layer for the 26M+ developers using AI coding tools (Cursor, Claude Code, Copilot, Bolt, Lovable, Replit Agent). These tools ship code fast but skip security — 53% of teams found vulnerabilities that passed review.

**Differentiation:** Free, fast, offline, AI-native. The anti-Snyk for indie devs.
- Snyk: $25-98/dev/mo, cloud-dependent, enterprise-focused
- Semgrep: re-licensed behind commercial terms, community backlash
- ShipSecure: $8/mo, URL-only (not source code), web-based
- VibeAppScanner: $5-29/mo, scans deployed apps (not CLI)
- **VibeCheck: Free CLI, zero deps, offline, source code + config, MIT**

**Moat:** Detection rules compound. Community contributions create network effects. "vibecheck" becomes the verb developers use before pushing.

**Revenue path:** Free CLI (distribution) → Pro features (revenue) → Team/Enterprise (scale).

---

## v0.2.0 — SHIPPED (2026-03-29)
> 1,879 lines, 30 files, 31 tests

- [x] 30+ detection rules: secrets (16), injection (6), auth (2), config (6), dotenv (3)
- [x] Python, JS/TS, .env, config file support
- [x] Colored terminal + JSON + SARIF output
- [x] GitHub Action (composite, configurable severity)
- [x] .vibeignore support
- [x] Published: PyPI (`pip install vibecheck-ai`) + GitHub (MIT)
- [x] Dogfooded on guardia-core (433 files, 233 findings, 5 criticals in .env)

---

## v0.3.0 — "The Vibe-Native Release"
> Goal: Own the "vibe coding security" category with patterns nobody else catches.

### Vibe-Coding-Specific Rules
- [ ] Supabase: RLS disabled/public, anon key in client code, service_role key exposed
- [ ] Firebase: open security rules (read/write: true), API key in client bundles
- [ ] Vercel: env vars in client components (NEXT_PUBLIC_ misuse), open API routes
- [ ] Netlify: exposed environment variables, open functions
- [ ] Prisma: raw queries without parameterization
- [ ] Drizzle: unsafe query construction patterns
- [ ] NextAuth/Auth.js: missing CSRF protection, weak session config
- [ ] Stripe: publishable key in server code, webhook secret in client

### Fix Prompts (Free — ShipSecure charges $8/mo for this)
- [ ] For each finding, generate a copy-paste prompt for Cursor/Claude/ChatGPT
- [ ] `vibecheck scan . --fix-prompts` outputs findings with AI-ready fix instructions
- [ ] Prompt includes: the vulnerability, the code context, the exact fix pattern
- [ ] Give it away free — this is the distribution hook that makes devs tell each other

### Pre-commit Hook
- [ ] `vibecheck hook install` — adds to .pre-commit-config.yaml or .husky
- [ ] Runs secrets + injection checks only (must be <2s)
- [ ] `vibecheck hook run` for manual pre-commit execution
- [ ] Skip with `--no-verify` (standard git behavior)

### DX Polish
- [ ] `vibecheck init` — generates .vibeignore with smart defaults for detected framework
- [ ] `vibecheck rules` — list all available checks with descriptions
- [ ] `vibecheck explain <check-name>` — detailed explanation + examples
- [ ] Baseline file: `vibecheck scan --baseline` saves current findings, future scans only show new ones
- [ ] `npx vibecheck` support (publish to npm as thin wrapper)

---

## v0.4.0 — "The IDE Release"
> Goal: Meet developers where they code — Cursor, VS Code, Windsurf.

### VS Code / Cursor Extension
- [ ] Real-time scanning on file save
- [ ] Inline diagnostics (red squiggles on vulnerable lines)
- [ ] Hover cards with fix prompts
- [ ] Quick-fix actions (apply the fix prompt directly)
- [ ] Status bar: finding count + severity indicator
- [ ] Extension marketplace publishing (VS Code + Open VSX)

### Watch Mode
- [ ] `vibecheck watch .` — continuous scanning, re-scan on file change
- [ ] Desktop notifications on new critical/high findings
- [ ] Pairs with IDE extension for terminal-first developers

### Framework Auto-Detection
- [ ] Detect project type from package.json / pyproject.toml / Cargo.toml
- [ ] Auto-enable framework-specific rules (Next.js, FastAPI, Express, Django, Flask)
- [ ] Skip irrelevant checks for the detected stack

---

## v0.5.0 — "The Community Release"
> Goal: Community-contributed rules become the moat.

### Custom Rules (YAML)
- [ ] Simple YAML rule format (inspired by Semgrep but much simpler):
  ```yaml
  id: supabase-rls-disabled
  severity: critical
  languages: [typescript, javascript]
  message: "Supabase table has RLS disabled"
  pattern: ".from('$TABLE').select("
  fix: "Enable RLS: ALTER TABLE $TABLE ENABLE ROW LEVEL SECURITY"
  ```
- [ ] `vibecheck rules add <path-to-yaml>` — add custom rules
- [ ] `vibecheck rules test <path-to-yaml>` — validate custom rules against test cases
- [ ] Rules directory: `.vibecheck/rules/*.yml` in project root

### Community Rule Registry
- [ ] GitHub repo: vibecheck-rules (community contributions)
- [ ] No CLA — just MIT + PR. Lower friction than Semgrep.
- [ ] Categories: frameworks, cloud providers, AI tools, general
- [ ] `vibecheck rules install <pack-name>` — install community rule packs
- [ ] Featured packs: supabase, firebase, nextjs, fastapi, express

### Rule Quality Metrics
- [ ] Track false positive rate per rule (from user feedback)
- [ ] Auto-disable rules with >20% false positive rate
- [ ] Community voting on rule accuracy

---

## v1.0.0 — "The Pro Release"
> Goal: Revenue. Free stays free. Pro adds team + AI features.

### Groq/LLM Integration (Pro)
- [ ] Context-aware analysis: LLM reads surrounding code to reduce false positives
- [ ] Natural language explanations: "This is dangerous because..." not just "SQL injection found"
- [ ] Auto-fix generation: LLM writes the actual fix, not just a prompt
- [ ] Confidence scoring: "87% likely a real vulnerability" vs "23% — probably safe"
- [ ] Configurable: `VIBECHECK_API_KEY` for Groq, or bring your own LLM

### Team Dashboard (Pro)
- [ ] Web dashboard: project overview, finding trends, team activity
- [ ] GitHub PR comments: bot posts findings inline on PRs
- [ ] Slack/Discord notifications on new critical findings
- [ ] Finding suppression: mark false positives, share across team
- [ ] Compliance reports: exportable security posture summary

### Pricing
- [ ] Free: CLI, all rules, SARIF, GitHub Action, fix prompts, pre-commit
- [ ] Pro ($9/mo): LLM analysis, dashboard, PR bot, Slack alerts
- [ ] Team ($29/mo): team management, shared suppressions, compliance reports
- [ ] Enterprise ($99/mo): SSO, audit log, SLA, dedicated support

---

## v2.0.0 — "The Platform" (2027)
> Goal: VibeCheck becomes the standard security layer for AI-generated code.

### MCP Server Mode
- [ ] Run VibeCheck as an MCP server — AI agents can scan code before deploying
- [ ] Tools: scan_file, scan_project, get_findings, explain_finding, suggest_fix
- [ ] Integration with Vigil: MCP observability feeds into Vigil awareness

### Runtime Scanning
- [ ] Scan deployed apps (like ShipSecure but free tier)
- [ ] DAST basics: open ports, exposed admin panels, missing headers
- [ ] Combine source + runtime findings for full picture

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

| Tool | Price | Approach | VibeCheck Advantage |
|------|-------|----------|-------------------|
| Snyk | $25-98/mo | Cloud SCA + SAST | Free, offline, faster, no vendor lock-in |
| Semgrep | Free-$40/mo | Rule-based SAST | Simpler rules, MIT license, no CLA |
| ShipSecure | $8/mo | URL scanner + fix prompts | CLI source scanner, free fix prompts |
| VibeAppScanner | $5-29/mo | Web-based deployed scan | CLI, offline, source code, free |
| ChakraView | Free | Open source CLI | More rules, framework detection, community |
| Bandit | Free | Python-only AST | Multi-language, more rule types |
| Aikido | Free/Paid | Platform + IDE | Lighter, no platform dependency |
| Snyk agent-scan | Free | MCP/agent config scanner | Broader scope (source + config + .env) |

**VibeCheck's unique position:** The only free, offline, multi-language CLI scanner specifically designed for vibe-coded apps, with AI-ready fix prompts and community rules. Nobody else combines all of these.

---

## Key Metrics to Track

| Metric | v0.2 (Now) | v0.3 Target | v1.0 Target |
|--------|-----------|-------------|-------------|
| PyPI downloads/week | 0 | 200 | 2,000 |
| GitHub stars | 0 | 100 | 1,000 |
| Detection rules | 30+ | 60+ | 150+ |
| Languages supported | 3 | 3 | 6 |
| Community rule packs | 0 | 0 | 10 |
| Tests | 31 | 60 | 150 |
| Pro subscribers | 0 | 0 | 100 |
| MRR | $0 | $0 | $900 |

---

## Distribution Plan (Launch Sequence)

### Phase 1: Awareness (v0.3 launch)
1. HN "Show HN: VibeCheck — security scanner for vibe-coded apps" (when HN account has karma)
2. Dev.to: "I Built a Security Scanner That Catches What Copilot Ships"
3. r/webdev, r/programming, r/netsec
4. Product Hunt
5. Twitter/X: demo videos (15s scan → findings → fix)

### Phase 2: Adoption (v0.4-v0.5)
6. VS Code / Cursor extension marketplace
7. awesome-security-tools PRs
8. Conference talks / blog posts about vibe coding security
9. Community rule contributions drive organic growth

### Phase 3: Revenue (v1.0)
10. Pro tier launch with LLM features
11. Team features for startups
12. Enterprise outreach

# Critik Roadmap
> AI-powered code security scanner. The critic your code needs.
> Last updated: 2026-04-02
> Last competitive recon: 2026-04-02

## Strategic Position

Critik is a lightweight, AI-native code security scanner targeting solo/indie developers at $9-15/mo — the segment every funded competitor ignores.

**The thesis is validated:** 53% of teams shipping AI-generated code found security issues post-review. 35 new CVEs in March 2026 alone from AI-generated code. 86% of AI-generated code failed XSS defenses. Real incident: Moltbook (Feb 2026) exposed 1.5M API keys via misconfigured Supabase in a vibe-coded app.

**Honest position:** 0 stars, 0 users, $0 revenue. Competing in a space with $2.5B+ combined funding. The thesis is right, but OpenAI, Anthropic, and GitHub are all building competing solutions with free/bundled distribution. Critik wins only by being faster, simpler, and specifically targeting developers who don't want platform lock-in.

**Differentiation:** Free CLI, zero-config, offline-capable, AI-native (two-pass: regex/AST + LLM review), model-independent (Groq/Llama 3.3 — not locked to OpenAI/Anthropic). Pre-commit hook + VS Code extension + GitHub Action. MIT licensed.

**Revenue path:** Free CLI (distribution) → Pro features (revenue). This is primarily a credibility/portfolio play that could generate modest revenue. It's not a venture-scale business as a solo founder.

---

## What's Shipped (v0.2 → v0.4)

Built v0.2 to v0.4 in ~10 days. 4,400 lines, 138 tests, published on PyPI + VS Code Marketplace.

**Core (free, open source):**
- 30+ detection rules: secrets (16), injection (6), auth (2), config (6), dotenv (3)
- Framework-specific: Supabase, Firebase, Next.js, NextAuth, Prisma, Stripe
- Two-pass AI analysis: regex/AST finds candidates, Groq/Llama 3.3 reviews with full context
- AI verdicts: confirmed / false_positive / needs_review with confidence + fix suggestions
- Output: colored terminal, JSON, SARIF
- CLI: scan, watch, init, explain, rules, hook install
- Baseline support (only show new findings)
- Custom YAML rules (.critik/rules/*.yml)
- Pre-commit hook integration
- GitHub Action (composite, configurable severity)
- .critikignore support

**VS Code / Cursor Extension (v0.4.0):**
- Inline diagnostics (red squiggles on vulnerable lines)
- Hover cards with fix hints
- Quick fix actions
- Status bar with finding count
- Scan on save, scan on open, workspace scan
- Published: marketplace.visualstudio.com/items?itemName=alexlaguardia.critik

**Distribution done:**
- [x] PyPI: `pip install critik` (v0.4.0)
- [x] VS Code Marketplace: alexlaguardia.critik
- [x] GitHub: public, MIT license
- [x] Dev.to article published
- [x] critik.dev landing page (CF Pages)
- [x] critik-site repo on GitHub

---

## The Competitive Reality

### The Funding Wall

| Competitor | Funding | Stars | Users | Price |
|---|---|---|---|---|
| Snyk | $1.2B | 5.5K | 2M+ devs, $408M rev | $25/dev/mo |
| SonarSource | $458M | 10.2K | Millions (legacy) | $2.5K+/yr |
| Semgrep | $193M | 14.3K | Unknown | Free OSS / $35/dev/mo |
| Endor Labs | $188M | Minimal | Enterprise | $10K+/yr |
| Aqua/Trivy | $135M+ | 31K | Massive | Free OSS |
| Aikido | $93.2M | Minimal | 100K teams | $250/mo min |
| Socket | $65M | N/A | 7.5K orgs | ~$25/mo |
| Qwiet AI | $58.3M | N/A | Unknown | Acquired by Harness |
| TruffleHog | $30M+ | 24.5K | Thousands | Free OSS / Enterprise |
| Pixee | $15M | N/A | Early | Free / Paid |
| **Critik** | **$0** | **0** | **0** | **Free / $9-15/mo** |

### Existential Threats (NEW — not in previous analysis)

These emerged in Q1 2026 and fundamentally change the landscape:

| Threat | What | Why It Matters |
|---|---|---|
| **OpenAI Codex Security** | Free AI security scanner for Pro/Enterprise users | Scanned 1.2M commits in 30 days. FREE. 792 critical findings found. |
| **Anthropic Claude Code Security** | AI code security for Enterprise/Team | Reads code "like a human researcher." Will likely expand to all tiers. |
| **GitHub AI CodeQL** | AI-powered detections added to CodeQL | Free for public repos. Expanding language coverage. |
| **ZeroPath** | YC S24, RSAC 2026 finalist, Paul Graham angel | Same AI-native SAST thesis. $200/mo but well-funded. |
| **Mend SAST** | MCP-integrated SAST | Plugs into Cursor, Claude Code, Copilot directly. |

### Free Tools That Cover the Basics

| Tool | Stars | What | Critik Overlap |
|---|---|---|---|
| Trivy | 31K | Container/IaC/secret scanner | Low (infra-focused) |
| Gitleaks | 24.4K | Secret detection | Partial (secrets only) |
| TruffleHog | 24.5K | Secret detection + verification | Partial (secrets only) |
| Semgrep OSS | 14.3K | Rule-based SAST | High (same problem space) |
| Bandit | 7.8K | Python security linter, 12.5M downloads/mo | Medium (Python-only) |
| SonarQube Community | 10.2K | Code quality + security | Medium |
| CodeQL | 8K+ | Semantic code analysis | Medium (GitHub-only) |

### What This Means for Critik

**The good:**
- Vibe coding narrative is HOT. Every major publication covered it in Q1 2026. The timing is perfect.
- The $9-15/mo solo/indie price point is genuinely unserved. Funded tools either ignore solos or charge $25+/dev.
- Two-pass architecture (regex/AST + LLM) is efficient and defensible on cheap infra (Groq).
- Zero-config "install and scan" is what HN commenters want (setup complexity is #1 complaint).
- VS Code/Cursor extension is the right distribution channel.

**The bad:**
- OpenAI Codex Security is free and already has massive adoption. If it becomes broadly available, it eats Critik's lunch.
- Anthropic will likely bundle security scanning into Claude Code — Critik's exact target audience.
- GitHub AI CodeQL is free for public repos and deeply integrated.
- Every established tool has a free tier. "Why pay $9/mo for Critik when Semgrep OSS is free?"
- ZeroPath has the same thesis with YC backing and Paul Graham's money.

**The honest ceiling:**
- As a solo founder with $0 funding competing against $2.5B+ in the space, Critik is a portfolio/credibility piece that can generate modest revenue.
- The big players entering means the window for an indie tool to become the "standard" is closing.
- Realistic revenue ceiling: $500-2K/mo from developers who want something lightweight, offline, and not locked to OpenAI/Anthropic/GitHub.

---

## Roadmap

### Phase 1: Get Users (NOW — April/May 2026)
> Goal: 50 GitHub stars, 200 PyPI downloads/week, 100 VS Code installs. Prove resonance.

**Distribution (finish what's started):**
- [ ] HN "Show HN" (karma-gated — build via comments first)
- [ ] ProductHunt launch
- [ ] Dev.to: "I Built a Security Scanner That Uses AI to Review Its Own Findings"
- [ ] Reddit: r/webdev, r/programming, r/netsec
- [ ] Demo video (15s scan → AI review → fix)

**Polish:**
- [ ] npm wrapper: `npx critik` (reach JS/TS developers)
- [ ] `critik diff` — scan only git-changed files (fast CI feedback)
- [ ] Config file support (.critik.yml for project-level settings)
- [ ] False positive rate tracking (build trust data)

**Positioning (critical):**
- Lead with "vibe coding security" angle — the narrative is hot RIGHT NOW
- Position against Codex Security/Claude Code Security: "offline, model-independent, no platform lock-in"
- Lead with free — revenue comes later

### Phase 2: Community + Revenue Signal (Month 2-4)
> Goal: 200 stars, 500 downloads/week, 500 VS Code installs, first 5-10 Pro subscribers.

**Community Rules Registry:**
- [ ] GitHub repo: critik-rules (MIT, no CLA)
- [ ] Categories: frameworks, cloud providers, AI tools
- [ ] `critik rules install <pack-name>` from registry
- [ ] Featured packs: supabase, firebase, nextjs, fastapi, express
- [ ] Invite contributions from security community

**Pro Features ($9/mo):**
- [ ] Unlimited AI analysis (free: 5/day)
- [ ] GitHub PR bot: post findings inline on pull requests
- [ ] Slack/Discord notifications on critical findings
- [ ] Stripe billing integration
- [ ] LLM auto-fix: generate actual code patches (not just prompts)

### Phase 3: Defend the Niche (Month 4-8)
> Goal: 500 stars, 20+ Pro subscribers ($180-300 MRR). Survive the platform security wave.

**Differentiation (what platforms CAN'T do):**
- [ ] Offline mode with local models (Ollama integration) — platforms require cloud
- [ ] Multi-model: scan with any LLM (Groq, local, OpenAI, Anthropic)
- [ ] Custom YAML rules + community registry — platforms are opinionated/locked
- [ ] CI/CD agnostic: GitHub, GitLab, Bitbucket, any git host
- [ ] Rule quality metrics: track false positive rates per rule, auto-disable noisy rules

**Don't build:**
- ~~Supply chain scanning~~ (Socket, Endor Labs own this with $250M+ combined)
- ~~Multi-language expansion~~ (stick to Python, JS/TS, config files — where vibe coding lives)
- ~~Enterprise tier~~ (nobody with enterprise needs is paying $99/mo for an indie tool)
- ~~MCP server mode~~ (navel-gazing — not a real user request)
- ~~Vigil integration~~ (build for users, not for yourself)

### Phase 4: Growth or Portfolio (Month 8-12)
> Decision gate: if <20 Pro subscribers, Critik becomes a portfolio piece. That's okay.

**If traction is real (>30 Pro subscribers):**
- [ ] Team features ($29/mo): shared suppressions, compliance reports
- [ ] Web dashboard: project overview, finding trends
- [ ] Consider targeting "AI coding tool" companies (Cursor, Bolt, Replit) as integration partners
- [ ] IDE extension for JetBrains (IntelliJ, PyCharm)

**If traction is weak:**
- Critik remains a strong portfolio piece and credibility builder
- VS Code extension installs + GitHub stars still compound career value
- Bug bounty experience (HackerOne, 0din) + Critik = "security expert" positioning
- Open-source everything, keep maintained, stop chasing revenue

---

## Pricing

### Free Tier (generous — distribution is the priority)
- Unlimited regex/AST scans
- 5 AI reviews per day
- VS Code extension (full features)
- Pre-commit hook
- GitHub Action
- All built-in rules + community rules
- JSON + SARIF output

### Pro — $9/mo
- Unlimited AI reviews
- GitHub PR bot (inline findings on PRs)
- Slack/Discord notifications
- LLM auto-fix (code patches)
- Priority support

### Why no Team/Enterprise yet
- 0 users. Build for solos first.
- Enterprise buyers won't pay $99/mo for an indie tool when Snyk/Semgrep exist.
- Revisit when there are 50+ individual subscribers asking for team features.

---

## Revenue Projections (realistic)

| Phase | Timeline | MRR | Driver |
|-------|----------|-----|--------|
| Distribution | Apr-May 2026 | $0 | Stars, downloads, installs |
| First Pro Users | Jun-Aug 2026 | $0-90 | HN/PH traffic, vibe coding narrative |
| Steady Niche | Sep-Dec 2026 | $90-500 | Word of mouth, community rules |
| Solo Ceiling | 2027 | $500-2K/mo | Without platform lock-in narrative holding |

Previous PBOARD had "Conservative: 5K installs, 3% conversion, $9/mo = $1,350/mo" and "Optimistic: 20K installs, 5%, $15/mo = $15,000/mo." Those assumed VS Code install counts that rival established tools with millions in marketing budgets. Revised to honest numbers.

**The real value of Critik may not be revenue:**
- Portfolio piece proving security expertise
- Credibility for bug bounty work (HackerOne, 0din)
- "Built a security tool" on resume/portfolio
- Open source contribution to the vibe coding security conversation
- Career positioning as security-aware developer

---

## Key Metrics

| Metric | Current | Q2 2026 Target | Q4 2026 Target |
|--------|---------|----------------|----------------|
| PyPI downloads/week | ~0 | 200 | 1,000 |
| GitHub stars | 0 | 50 | 300 |
| VS Code installs | 0 | 100 | 500 |
| Built-in checks | 11 | 11 | 15 |
| Community rule packs | 1 | 5 | 10 |
| Tests | 138 | 150 | 180 |
| Pro subscribers | 0 | 0 | 10-20 |
| MRR | $0 | $0 | $90-180 |

---

## What's NOT on the Roadmap Anymore

| Cut | Why |
|-----|-----|
| Multi-language expansion (Go, Rust, Ruby, PHP, Java, Swift) | Years of work. Stay where vibe coding lives: Python, JS/TS, config. |
| Supply chain scanning | Socket ($65M) and Endor Labs ($188M) own this. Don't compete. |
| MCP server mode | Building for yourself, not users. |
| Vigil integration | Same — build for users. |
| Enterprise tier ($99/mo) | No enterprise buyer picks an indie tool at $99 over Snyk/Semgrep. |
| $15,000/mo optimistic projection | Fantasy. OpenAI/Anthropic entering puts a hard ceiling on indie tools. |
| v2.0 "The Platform" | Premature. Get 50 stars first. |

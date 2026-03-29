# I Built a Security Scanner That Uses AI to Review Its Own Findings

Every AI coding tool ships code fast. None of them check if it's safe.

I built [Critik](https://github.com/AlexlaGuardia/Critik) — an open-source security scanner specifically for vibe-coded apps. It runs regex and AST analysis to find vulnerabilities, then sends each finding to an LLM that reviews it with full file context. The AI confirms real issues, dismisses false positives, and explains *why* in plain English.

`pip install critik` and you're scanning in 30 seconds.

---

## The Problem Nobody's Talking About

53% of teams that shipped AI-generated code later discovered security issues that passed review. Georgia Tech's Vibe Security Radar tracked 74 CVEs directly from AI coding tools in Q1 2026 — 6 in January, 15 in February, 35 in March. The curve is accelerating.

Here's what I kept seeing when I scanned vibe-coded projects:

- **Hardcoded API keys** — Cursor generates a Supabase client and pastes the service_role key directly in the file
- **SQL injection via f-strings** — Copilot autocompletes `db.execute(f"SELECT * FROM users WHERE id = {user_id}")` without hesitation
- **Firebase rules wide open** — Bolt scaffolds `read: true, write: true` and nobody changes it
- **NEXT_PUBLIC_ prefix on secrets** — the env var that exposes your database URL to every browser

These aren't edge cases. These are the *default patterns* AI tools generate.

## Why Existing Tools Don't Work Here

**Snyk** charges $25-98/dev/mo and is built for enterprises. Solo devs and small teams can't justify that.

**Semgrep** is powerful but requires writing custom rules in a DSL. The learning curve is steep and they recently relicensed behind commercial terms.

**npm audit** is, according to Dan Abramov, "broken by design" — it reports devDependency issues that can't affect production.

**Bandit** (Python-only) and **ESLint security plugins** catch some patterns but have no context awareness. They flag `eval()` in a test fixture the same way they flag `eval(user_input)` in a request handler.

That last point is the key problem. Static scanners are noisy. They produce so many false positives that developers learn to ignore them — which means they also ignore the real ones.

## Two-Pass Architecture: Regex First, AI Second

Critik runs in two passes:

**Pass 1 — Static Analysis (fast, offline, free)**

Regex patterns and Python AST parsing catch the obvious stuff: hardcoded secrets (16 patterns including AWS, Stripe, OpenAI, Anthropic keys), SQL injection, command injection, eval/exec, XSS vectors, framework misconfigurations (Supabase, Firebase, Next.js, Prisma, Stripe).

This pass runs in milliseconds, works offline, and requires no API key.

**Pass 2 — AI Review (optional, context-aware)**

When you add `--ai`, Critik sends each finding to Groq's Llama 3.3 70B with the *full file content* as context. The LLM acts as a security analyst:

- **Verdict**: confirmed, false_positive, or needs_review
- **Confidence**: 0-100%
- **Explanation**: "This eval() parses trusted JSON config from a local file" vs "This eval() takes unsanitized user input from req.query"
- **Specific fix**: actual code, not generic advice
- **Severity adjustment**: upgrades or downgrades based on real risk

The AI doesn't replace the scanner — it reviews the scanner's work. Like having a senior security engineer look over automated results.

## What This Actually Looks Like

Here's a scan of a test project with intentional vulnerabilities:

```
$ critik scan . --ai

  Critik v0.4.0 — scanned 7 files  [AI]

  CRITICAL  nextjs-public-secret
  app/config.ts:18  Secret exposed to browser via NEXT_PUBLIC_ prefix
  | 18 | const key = process.env.NEXT_PUBLIC_SECRET_API_KEY
  CONFIRMED (95%)
  > The NEXT_PUBLIC_ prefix exposes this API key to every browser.
  Fix: Rename to SECRET_API_KEY and access server-side only

  CRITICAL  aws-access-key              (dimmed — false positive)
  tests/fixtures/bad_secrets.py:2  AWS access key detected
  FALSE POS (100%)
  > This file is in tests/fixtures — fake credentials for testing.

  HIGH      sql-fstring
  app/db.py:6  SQL injection via f-string in execute()
  | 6 | db.execute(f"SELECT * FROM users WHERE id = {user_id}")
  CONFIRMED (95%)
  > This f-string takes unsanitized input, allowing SQL injection.
  Fix: db.execute('SELECT * FROM users WHERE id = ?', (user_id,))

  ─────────────────────────────────────────────
  7 files scanned in 2714ms — 23 findings: 10 critical, 8 high, 5 medium
  AI analysis: 7 confirmed, 16 false positives
```

Without AI: 23 findings, developer overwhelmed, ignores all of them.
With AI: 7 real issues, 16 dismissed with explanations, developer fixes the 7.

That's the difference.

## How the AI Prompt Works

The trick is giving the LLM enough context to make good decisions. Each API call includes:

1. **The full file content** (up to 8K chars) — so the model sees imports, function signatures, and data flow
2. **All findings for that file** — batched together so the model understands the full picture
3. **A system prompt** that teaches security analysis patterns — test fixtures are usually safe, .env files are expected to have secrets, NEXT_PUBLIC_ vars are intentionally client-exposed

Findings are grouped by file, one API call per file. This keeps token usage low and gives the model maximum context.

The model runs at temperature 0.2 (low creativity, high consistency) and returns structured JSON. If the API is rate-limited or down, Critik falls back gracefully to regex-only results.

## What It Catches Today

| Category | Patterns | Examples |
|----------|----------|----------|
| Secrets | 16 | AWS, GitHub, OpenAI, Anthropic, Stripe, Slack, DB URLs, JWTs, private keys |
| Injection | 6 | SQL via f-string/concat, eval(), exec(), os.system(), subprocess shell=True, XSS |
| Frameworks | 8 | Supabase RLS, Firebase open rules, NEXT_PUBLIC_ secrets, NextAuth config, Prisma raw queries, Stripe webhook verification |
| Config | 6 | NODE_ENV in source, insecure cookies, open CORS, debug mode |
| Auth | 2 | Missing auth on API routes, open endpoints |
| Dotenv | 3 | Exposed .env files, sensitive vars without encryption |

## It's Free

The CLI is free. The AI analysis is free (Groq's free tier). The GitHub Action is free. MIT license.

```bash
pip install critik
critik scan .                # regex/AST only — offline, instant
critik scan . --ai           # + AI analysis (needs GROQ_API_KEY)
critik scan . --format fix   # copy-paste fix prompts for Cursor/Claude
```

There's also a pre-commit hook (`critik hook install`) that scans staged files before every commit, and SARIF output for CI/CD integration.

## Why I Built This

I do bug bounty hunting on HackerOne and 0din. The vulnerabilities I find in production apps are overwhelmingly the same patterns AI tools generate by default. Hardcoded keys, missing auth, SQL injection, open configs.

The irony: AI coding tools are simultaneously the biggest source of new vulnerabilities *and* the best tool for detecting them. A regex can find `eval()` — but only an LLM can tell you whether the eval is actually dangerous in context.

Critik is the scanner I wanted to exist. Now it does.

---

**GitHub**: [AlexlaGuardia/Critik](https://github.com/AlexlaGuardia/Critik)
**PyPI**: `pip install critik`
**License**: MIT

If you're building with AI coding tools, run `critik scan .` on your project. You might be surprised.

# I Built a Security Scanner That Uses AI to Review Its Own Findings

Every AI coding tool ships code fast. None of them check if it's safe.

I built [Critik](https://github.com/AlexlaGuardia/Critik) — an open-source security scanner that catches what your AI writes and your review misses. Regex and AST find the candidates. An LLM reviews each one with full file context, confirms the real problems, kills the false positives, and explains why in plain English.

`pip install critik` and you're scanning in 30 seconds.

---

## The Numbers Are Ugly

53% of teams that shipped AI-generated code later found security issues that passed review. Georgia Tech's Vibe Security Radar tracked 74 CVEs from AI coding tools in Q1 2026 alone — 6 in January, 15 in February, 35 in March. Accelerating.

Here's what I keep finding when I scan AI-built projects:

- **Hardcoded API keys** — Cursor generates a Supabase client and pastes the service_role key right in the file
- **SQL injection via f-strings** — Copilot autocompletes `db.execute(f"SELECT * FROM users WHERE id = {user_id}")` without blinking
- **Firebase rules wide open** — Bolt scaffolds `read: true, write: true` and nobody touches it
- **NEXT_PUBLIC_ prefix on secrets** — the env var that hands your database URL to every browser

Not edge cases. Default patterns.

## The Tools That Exist Don't Fix This

**Snyk** charges $25-98/dev/mo. Built for enterprises with procurement budgets.

**Semgrep** is powerful. Also requires writing custom rules in a DSL. Steep curve. Recently relicensed behind commercial terms.

**npm audit** is, in Dan Abramov's words, "broken by design" — flags devDependency issues that can't touch production.

**Bandit** and **ESLint security plugins** catch patterns but have zero context. They flag `eval()` in a test fixture the same way they flag `eval(user_input)` in a request handler.

That last one is the real problem. Static scanners are noisy. Developers learn to ignore them. Which means they ignore the real findings too.

## Two Passes. One Scanner.

**Pass 1 — Static (fast, offline, free)**

Regex patterns and Python AST parsing. Hardcoded secrets (16 patterns — AWS, Stripe, OpenAI, Anthropic), SQL injection, command injection, eval/exec, XSS, framework misconfigs. Runs in milliseconds. No API key needed.

**Pass 2 — AI Review (optional, the whole point)**

Add `--ai` and each finding goes to Groq's Llama 3.3 70B with the *full file* as context. The model acts as a security analyst:

- **Verdict**: confirmed, false_positive, or needs_review
- **Confidence**: 0-100%
- **Why**: "This eval() parses trusted JSON config from a local file" vs "This eval() takes unsanitized user input from req.query"
- **Fix**: actual code, not generic advice

The AI doesn't replace the scanner. It reviews the scanner's work.

## What It Looks Like

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

Without AI: 23 findings. Developer overwhelmed. Ignores all of them.

With AI: 7 real issues. 16 dismissed with reasons. Developer fixes what matters.

## Under the Hood

Each API call sends the full file content (up to 8K chars) plus all findings for that file. One call per file — keeps tokens low, context high.

The model sees imports, function signatures, data flow. It knows test fixtures are probably safe, `.env` files are expected to have secrets, and `NEXT_PUBLIC_` vars are intentionally client-exposed.

Temperature 0.2. Structured JSON back. If the API is down, Critik falls back to regex-only. No crash, no hang.

## What It Catches

| Category | Patterns | Examples |
|----------|----------|----------|
| Secrets | 16 | AWS, GitHub, OpenAI, Anthropic, Stripe, Slack, DB URLs, JWTs, private keys |
| Injection | 6 | SQL via f-string/concat, eval(), exec(), os.system(), subprocess shell=True, XSS |
| Frameworks | 8 | Supabase RLS, Firebase rules, NEXT_PUBLIC_ secrets, NextAuth, Prisma raw, Stripe webhooks |
| Config | 6 | NODE_ENV in source, insecure cookies, open CORS, debug mode |
| Auth | 2 | Missing auth on routes, open endpoints |
| Dotenv | 3 | Exposed .env, sensitive vars unencrypted |

## Free. All of It.

```bash
pip install critik
critik scan .                # regex/AST only — offline, instant
critik scan . --ai           # + AI review (needs GROQ_API_KEY)
critik scan . --format fix   # copy-paste fix prompts for Cursor/Claude
```

Pre-commit hook: `critik hook install`. SARIF output for CI/CD. GitHub Action included. MIT license.

## Why I Built This

I hunt bugs on HackerOne and 0din. The vulnerabilities I find in production are the same patterns AI tools ship by default. Hardcoded keys. Missing auth. SQL injection. Open configs.

The irony: AI coding tools are the biggest source of new vulnerabilities *and* the best tool for catching them. A regex finds `eval()`. Only an LLM can tell you if it's dangerous.

Critik is the scanner I wanted. Now it exists.

---

**Website**: [critik.dev](https://critik.dev)
**GitHub**: [AlexlaGuardia/Critik](https://github.com/AlexlaGuardia/Critik)
**PyPI**: `pip install critik`

Run `critik scan .` on your project. You might not like what you find.

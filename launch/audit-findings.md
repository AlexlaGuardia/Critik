# Critik Audit — "I scanned 9 popular open-source AI app templates"

> Working notes for the launch writeup. Data gathered 2026-05-31.
> Scanner: Critik v0.4.0 + `.env` double-count fix.
>
> ⚠️ REDACTED FOR PUBLIC SAFETY: one repo ("Repo L") had a real, undisclosed
> finding. Its name + the exact location are withheld here until a responsible
> disclosure is sent and remediated. Full details live in the gitignored note
> `launch/disclosure-*.md` (never committed). Un-redact only after fix lands.

## The thesis (honest, contrarian, defensible)

The most-forked AI app templates throw **200+ raw findings** between them — but
**90%+ is noise**: test fixtures, `.env.example` placeholders, framework-standard
patterns, and key-name false positives. Genuine exploitable issues are *rare*.

That's the real story — and it's *more* interesting than "popular apps are full of
vulns" (which is false and would get torn apart on HN). The noise is exactly why
developers tune out scanners, and why a **verification layer** (AI second-pass)
matters more than another regex pack. This is Critik's whole bet.

## Repos scanned (shallow clone, 2026-05-31)

vercel/ai-chatbot · supabase-community/vercel-ai-chatbot · mckaywrigley/chatbot-ui
· adrianhajdin/saas-template · wyattm14/chatbot-template · jirhegg/ai-saas-starter-kit
· steven-tey/novel · miurla/morphic · **Repo L** (a large self-host AI chat app —
name withheld pending responsible disclosure of one real finding)

## Raw scan scorecard (high+ severity, after .env fix)

| Repo | CRIT | HIGH | MED |
|---|---|---|---|
| adrianhajdin/saas-template | 0 | 0 | 0 |
| jirhegg/ai-saas-starter-kit | 0 | 0 | 20 |
| Repo L (withheld) | 2 | 77 | 51 |
| mckaywrigley/chatbot-ui | 0 | 0 | 18 |
| miurla/morphic | 2 | 5 | 2 |
| steven-tey/novel | 0 | 0 | 2 |
| supabase-community/vercel-ai-chatbot | 0 | 0 | 5 |
| vercel/ai-chatbot | 0 | 2 | 6 |
| wyattm14/chatbot-template | 0 | 1 | 1 |

## AI-triage deep dives

### miurla/morphic — 7 crit/high, **0 real** (the hero example)
- `lib/db/index.ts:28` CRIT "DB connection string w/ creds" → literal `postgres://user:pass@localhost:5432/testdb` test fallback. AI: **false_positive (90)**. ✅
- `vitest.setup.ts:7` CRIT → same localhost test dummy. AI: **false_positive (100)**. ✅
- `.env.local.example:20/57/67` HIGH → `OPENAI_API_KEY=[YOUR_OPENAI_API_KEY]` bracket placeholders in an EXAMPLE file. AI: **false_positive (100)**. ✅
- `.env.local.example:90` HIGH "Secret value for 'ENABLE_AUTH'" → boolean flag, key contains "auth". AI: **false_positive (100)**. ✅
- `theme-provider.tsx:162` HIGH dangerouslySetInnerHTML → next-themes nonce'd anti-FOUC script (safe, static). AI: **confirmed (90)** ❌ — the one miss. Honesty hook.

### vercel/ai-chatbot — 2 high
- `auth.ts:1` HIGH "NextAuth without explicit secret" → AI: **confirmed (90)**. Real *category* (hardening), debatable as a vuln. Needs human.
- `layout.tsx:65` HIGH dangerouslySetInnerHTML → AI: **false_positive**. ✅ (Note: same pattern it wrongly confirmed in morphic — model inconsistency, worth showing.)

### Repo L (large self-host AI chat app — name withheld pending disclosure) — 2 crit
- A `*.test.ts` fixture with `private_key: '...TEST...'`. Obvious fixture. FP.
- A committed identity-provider JWT signing private key in the self-host deploy template. **The one genuine finding in the batch.** Exact path + repo in the gitignored `launch/disclosure-*.md` — withheld here until reported + remediated.

## Critik precision bugs this audit surfaced (fix before launch)

1. **`.env.local.example` not recognized as an example file** → graded HIGH like a real `.env`. Should match any `.env*.example` / `*.example` / `*.sample` / `*.template`, `.env.local.example`, etc.
2. **Bracket-style placeholders `[YOUR_KEY]` not filtered** → PLACEHOLDER_PATTERNS only catches `your_`, `<...>`. Add `[...]`, `{{...}}`, `__...__`.
3. **Flag-key false positives** → `ENABLE_AUTH`, `AUTH_URL`, `*_ID`, `*_ISSUER`, `*_URL`, `*_ENABLED` match SECRET_KEY_NAMES but aren't secrets. Tighten: require the *value* to look secret-ish (entropy/length) or exclude obvious non-secret suffixes.
4. **Test-file / fixture awareness** → `*.test.*`, `*.spec.*`, `vitest.setup.*`, `conftest.py`, localhost connection strings should be downgraded.
5. **AI prompt inconsistency** on framework-standard `dangerouslySetInnerHTML` (next-themes / analytics inline scripts). Confirmed in one repo, FP in another. Add pattern guidance.

## RESULTS — precision fixes (commit pending)

Fixed bugs 1–4 in `dotenv.py` + `secrets.py` (138/138 tests still green):
- `.env*.example`/`.sample`/`.template`/`.dist` recognized as example files
- bracket/brace/dollar placeholders `[X]` `<X>` `{{X}}` `${X}` `__X__` filtered
- flag/url/id keys (`ENABLE_AUTH`, `AUTH_URL`, `*_ISSUER`, `*_ID`…) excluded; connection-string keys still flagged
- loopback DB connection strings (`@localhost`) skipped
- secrets in `*.test.*`/`*.spec.*`/`*.setup.*`/`conftest.py` demoted to LOW

**Before → after across all 9 repos (crit+high):**

| | CRIT | HIGH | crit+high |
|---|---|---|---|
| before | 4 | 85 | 89 |
| after | 1 | 19 | **20** |

**78% of the scary-tier findings were noise.** And the cut was surgical:
- Repo L: the **real** committed JWT signing key (details in the gitignored disclosure note) **stayed flagged**; the test-fixture key (`*.test.ts`, body `TEST`) got demoted. Signal kept, noise dropped.
- morphic: 7 → 1 (all 6 env/secret false-positives gone; the 1 left is the next-themes `dangerouslySetInnerHTML`, a safe-but-flaggable source pattern).

The before/after IS the launch hook: *"Same scanner, one evening of precision work — 78% fewer false alarms, zero real findings lost."*

## Next steps
- [ ] Draft the Dev.to / Show HN piece around the before/after + "noise is the real problem" thesis
- [ ] Send the responsible-disclosure note (Repo L) before any writeup names it; un-redact these notes only after remediation
- [ ] (optional) Tune `injection.py` for framework-standard `dangerouslySetInnerHTML` (next-themes/analytics) — the remaining FPs
- [ ] Bump version, rebuild dist, republish (PyPI + VS Code) once writeup is ready

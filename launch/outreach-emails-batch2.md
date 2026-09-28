# Critik Outreach — Batch 2 (Apr 30, 2026)

Krowdbase pattern: short, specific to their listicle, no fluff, ends with "happy to send X if helpful."

---

## Target 1: Augment Code (press@augmentcode.com)

**Why:** They published "10 Open Source AI Code Review Tools Tested on a 450K-File Monorepo" — Critik fits the exact niche they tested. Their analysis explicitly noted gaps in pattern-based scanners that Critik's two-pass AI review addresses.

**Subject:** Open-source AI code security scanner missing from your roundup

Hi,

Saw your post on open-source AI code review tools tested on the 450K-file monorepo. Solid breakdown — your point about the cross-service architectural analysis gap was spot on.

Wanted to share Critik in case you do a follow-up. It's an open-source AI code security scanner aimed at the gap your analysis surfaced: pattern-based tools generate noise, and most AI tools require expensive vendor lock-in.

Critik runs a two-pass architecture: regex/AST first to catch hardcoded secrets, SQL injection, and XSS patterns, then a Llama 3.3 70B AI review with full file context to filter false positives. Free, open source, MIT, not locked to any AI provider.

Hits: zero config (`pip install critik && critik scan`), VS Code extension with inline diagnostics, GitHub Action, pre-commit hook, custom YAML rules.

Live at critik.dev. PyPI: `critik`. 138 tests, 4,400 lines.

Happy to send architecture details, screenshots, or a benchmark on your monorepo if useful.

Alex La Guardia
critik.dev | github.com/AlexlaGuardia/critik

---

## Target 2: AppSec Santa / Suphi Cankurt (LinkedIn DM)

**Why:** Independent AppSec aggregator. Lists 13 AI security tools currently. Critik is not yet listed. Author is reachable via LinkedIn (https://www.linkedin.com/in/suphiozgur/).

**LinkedIn DM:**

Hi Suphi,

I read your AppSec Santa AI security tools roundup. Concise, well-structured, the kind of resource I wish more of the AppSec space had.

Wanted to flag Critik in case it's a fit. It's a new open-source AI code security scanner built around the vibe-coding gap: AI-generated code is shipping with security issues 53% of the time, and most existing scanners don't reason about AI-generated code patterns.

Two-pass: regex/AST first, then Llama 3.3 review with file context. Zero config. Free, MIT, not vendor-locked. critik.dev.

If it doesn't fit your list, no worries — would still appreciate any feedback you have on the positioning.

Alex
critik.dev

---

## Target 3: awesome-static-analysis (PR submission)

**Top destination:** github.com/mre/awesome-static-analysis (most-starred, powers analysis-tools.dev)

**PR title:** Add Critik — AI-powered code security scanner

**PR body (markdown entry):**

```markdown
- [Critik](https://critik.dev) — Open-source AI-powered code security scanner. Two-pass architecture: regex/AST + LLM review (Llama 3.3) with file context. Zero config CLI, VS Code extension, GitHub Action, pre-commit hook. Custom YAML rules. MIT license.
```

**Notes for PR:**
- Add to "Multi-Language" section under Security Tools
- Format must match existing entries (alphabetical, consistent description length)
- Include badges if other entries have them: PyPI version, GitHub stars, license

---

## Target 4: awesome-security/awesome-static-analysis (PR submission)

Same pattern as Target 3. Different fork, different maintainer. Worth submitting to both for breadth.

---

## Targets parked (no contact path found):

- **Code-quality.io** — no public contact email
- **Endor Labs / OX Security / Corgea** — competitors, won't list Critik
- **Checkmarx / Cycode / Snyk blog** — corporate competitors, won't list

## Pattern notes for future outreach:

1. Read THEIR article first. Reference a specific point they made.
2. Position Critik against the gap they identified, not the competition.
3. Open with "saw your X, here's why Y" not "I built a thing".
4. End with concrete offer (architecture details, screenshots, benchmark on their data).
5. Keep under 200 words.

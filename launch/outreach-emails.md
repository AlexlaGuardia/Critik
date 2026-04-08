# Critik — Listicle Outreach Emails

## Target List

### Tier 1: Best fit (free/indie/developer-focused lists)
1. **CodeAnt.ai** — codeant.ai/blogs/ai-secure-code-review-platforms ("Best 7 AI Code Review Tools for Security")
2. **GetPanto.ai** — getpanto.ai/blog/best-ai-code-review-tools ("Best AI Code Review Tools of 2026")
3. **Krowdbase** — krowdbase.com/best-ai-vulnerability-scanner-software ("Best AI Vulnerability Scanner Software")

### Tier 2: Bigger publications (less likely to respond)
4. **TrueFoundry** — truefoundry.com/blog/best-ai-code-security ("Best AI Code Security Tools for Enterprise")
5. **Apiiro** — apiiro.com/blog/top-code-security-tools/ ("Top 11 code security tools in 2026")

### Tier 3: Competitor pages — skip
- Cycode, Checkmarx (enterprise, self-promoting)

---

## Email Template

**Subject:** Open-source AI code security scanner for your tools list

Hi [name/team],

Saw your roundup of AI code security tools — good list. Thought Critik might be worth a mention.

It's an open-source, two-pass code security scanner I built for the vibe-coding era. First pass uses regex + AST to catch hardcoded secrets, SQL injection, and XSS patterns. Second pass runs an AI review (Llama 3.3 70B via Groq) with full file context to filter false positives and catch logic-level vulnerabilities.

What makes it different:
- Zero config: `pip install critik && critik scan`
- Not locked to any AI provider (works with Groq, local models, etc.)
- VS Code extension with inline diagnostics
- GitHub Action + pre-commit hook
- Custom YAML rules for team-specific patterns
- Free and open source (MIT license)

Live at critik.dev. PyPI: critik. VS Code Marketplace: critik. 138 tests, 4,400 lines.

Happy to provide any details for the article. Screenshots, architecture diagram, whatever helps.

Alex La Guardia
critik.dev | github.com/AlexlaGuardia/critik

---

## G2 / AlternativeTo / Slant

Also create free listings on:
- **AlternativeTo** — alternativeto.net (list as alternative to Snyk, Semgrep, Bandit)
- **Slant** — slant.co (comparison platform)
- **SourceForge** — sourceforge.net (open source directory)
- **LibHunt** — libhunt.com (dev tool comparison)

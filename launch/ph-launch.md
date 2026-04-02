# Critik - ProductHunt Launch Kit

## Product Name
Critik

## Tagline (under 60 chars)
Security scanner for AI-generated code

## Description

Critik catches the security issues that AI coding tools ship by default - hardcoded secrets, SQL injection, missing auth, open CORS, exposed .env files.

Two-pass approach: regex + AST finds candidates in milliseconds, then an LLM reviews each one with full file context to filter false positives and explain what's actually dangerous.

`pip install critik && critik scan .`

No account. No config. No dashboard to learn. Works offline. Also available as a VS Code extension and GitHub Action.

Free tier: 5 scans/day. Pro: unlimited + Slack alerts.

## Topics
- Developer Tools
- Artificial Intelligence
- Open Source
- Cybersecurity
- Code Review

## Links
- Website: https://critik.dev
- GitHub: https://github.com/AlexlaGuardia/critik
- PyPI: https://pypi.org/project/critik/
- VS Code: https://marketplace.visualstudio.com/items?itemName=alexlaguardia.critik

## Maker Comment (first comment after launch)

I built Critik because I kept finding the same security issues in AI-generated code.

Copilot autocompletes SQL injection. Cursor pastes service_role keys right in the file. Bolt scaffolds Firebase rules wide open. These aren't edge cases - they're default patterns.

The existing tools don't serve individual developers. Snyk charges $25-98/dev/mo. Semgrep requires writing custom rules in a DSL. npm audit is broken by design. And they all flag test fixtures the same way they flag production code.

Critik's approach: fast static scanning finds candidates, then AI reviews each one with the full file as context. It knows the difference between `eval()` in a test and `eval(user_input)` in a request handler. 90% false positive reduction compared to regex-only scanning.

53% of teams that shipped AI-generated code later found security issues that passed review. 74 CVEs from vibe-coded apps in Q1 2026 alone.

Try it: `pip install critik && critik scan .`

Open source. Free tier included. Built by a bug bounty hunter who got tired of finding the same vulnerabilities.

## Gallery Image Order
1. gallery-1-scan.png - Basic scan showing findings with severity + fixes
2. gallery-2-ai.png - AI review mode filtering false positives (the differentiator)
3. gallery-3-comparison.png - Critik vs Snyk vs Semgrep comparison
4. gallery-4-og.png - Brand/logo image

## Launch Timing
Best days: Tuesday, Wednesday, or Thursday
Best time: 12:01 AM PST (ProductHunt resets daily at midnight PST)
Avoid: Fridays, weekends, holidays

## Post-Launch Checklist
- [ ] Share PH link on LinkedIn
- [ ] Share PH link in Dev.to article comments
- [ ] Reply to every comment on PH within first 24 hours
- [ ] Update critik.dev with "Featured on ProductHunt" badge if applicable

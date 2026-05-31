---
title: "I scanned 9 popular open-source AI app templates. The scary part wasn't the vulnerabilities."
tags: security, ai, opensource, webdev
canonical_url: https://critik.dev/blog/scanning-ai-templates
---

# I scanned 9 popular open-source AI app templates. The scary part wasn't the vulnerabilities.

Everyone is shipping AI-generated code right now, and most of it goes out with little to no security review. So I did the obvious thing: I grabbed nine of the most-forked open-source AI app templates (the chatbot starters, the SaaS boilerplates, the "deploy to Vercel in one click" kits) and ran a security scanner over all of them.

I expected a horror show of leaked keys and injection bugs. That's not what I found. The real story turned out to be more useful, and it's the reason most developers quietly ignore security scanners.

Quick disclosure before anything else: I maintain the scanner I used ([Critik](https://critik.dev), open source, MIT). So read this as "what I learned pointing my own tool at real code," not a neutral product review. The lesson humbled my own tool more than it embarrassed anyone else's repo.

## The raw numbers look terrifying

Across the nine repos, the scanner flagged nearly 200 findings. Filtered to just the scary tier (critical and high severity), here's the scorecard:

| Repo | CRIT | HIGH |
|---|---|---|
| vercel/ai-chatbot | 0 | 2 |
| supabase-community/vercel-ai-chatbot | 0 | 0 |
| mckaywrigley/chatbot-ui | 0 | 0 |
| adrianhajdin/saas-template | 0 | 0 |
| wyattm14/chatbot-template | 0 | 1 |
| jirhegg/ai-saas-starter-kit | 0 | 0 |
| steven-tey/novel | 0 | 0 |
| miurla/morphic | 2 | 5 |
| Repo L (a large self-host AI chat app) | 2 | 77 |

If you stopped here, you'd write the clickbait version: "Popular AI templates riddled with critical vulnerabilities!" Plenty of security marketing works exactly like that. The count is real. The conclusion would be a lie.

## Then I read the findings

I went through every critical and high by hand. Here is what they actually were.

**A "critical database connection string with credentials":**

```ts
const connectionString =
  process.env.DATABASE_URL ??
  (isTest ? 'postgres://user:pass@localhost:5432/testdb' : undefined)
```

That's a localhost fallback used only in tests. There is no credential here. The same string appears in a `vitest.setup.ts` file, flagged again.

**A "high severity exposed secret":**

```
# .env.local.example
OPENAI_API_KEY=[YOUR_OPENAI_API_KEY]
```

It's a placeholder, in a file whose entire job is to be a placeholder. The scanner didn't recognize `.env.local.example` as an example file, and didn't recognize `[YOUR_OPENAI_API_KEY]` as a placeholder.

**Another "exposed secret":**

```
ENABLE_AUTH=true
```

Flagged as "secret value for ENABLE_AUTH" because the key contains the substring "auth." It's a boolean feature flag.

**A "high severity XSS vector":** a `dangerouslySetInnerHTML` call. It was the standard [next-themes](https://github.com/pacocoursey/next-themes) anti-flash script: a static, nonce'd inline script with no user input anywhere near it. Every Next.js app with dark mode has this. It is not an XSS vector.

**A "critical private key in source code":**

```ts
// inside *.test.ts
private_key: '-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----'
```

The body of the key is the literal word `TEST`.

You see the pattern. Test fixtures, example files, framework-standard code, and dumb substring matches. This is what "200 findings" is mostly made of. And one large monorepo (Repo L) produced the bulk of the raw volume all by itself, almost entirely from docker-compose example files and test data.

This is the actual reason security scanners get ignored. It isn't that they miss things. It's that they cry wolf so often that the real wolf gets lost in the noise. A tool that reports seven critical issues, six of which are fake, has not made you safer. It has trained you to dismiss the seventh.

## There was a real one

Out of everything, one finding was genuine, and it's a good example of the kind of thing that does matter.

In Repo L, the self-host deployment template ships an identity/SSO bootstrap file that contains a real RSA private key, the one used to sign the JWTs the auth server issues. Because the key is committed to the repo, anyone who deploys that stack as-is is signing tokens with a key that is public knowledge. An attacker who reads the repo can forge valid tokens for any unmodified deployment. That's an authentication bypass for downstream self-hosters, not a hypothetical.

I've reported this privately to the maintainers and I'm withholding the project's name until it's fixed. The point for this post is the contrast: one real, serious issue, sitting underneath dozens of fake criticals that would have buried it.

## So I fixed my scanner instead of writing the clickbait

The audit was supposed to produce a blog post. Instead it produced a bug list for my own tool. Every false positive above is a precision failure I could fix:

- Recognize `.env*.example`, `.sample`, `.template`, `.dist` as example files.
- Filter wrapped placeholders: `[VALUE]`, `<VALUE>`, `{{VALUE}}`, `${VALUE}`, `__VALUE__`.
- Stop treating feature flags, URLs, public IDs, and issuers as secrets just because the key name contains "auth" or "key." Keep flagging genuine connection strings.
- Skip loopback database URLs (`@localhost`); that's dev config, not a leak.
- Demote secrets found in `*.test.*`, `*.spec.*`, `*.setup.*`, and `conftest.py`. A dummy key in a fixture is not a production incident.

One evening of work. Here's the before and after across the same nine repos:

| | critical + high |
|---|---|
| before | 89 |
| after | **20** |

A 78% cut in the scary tier. And the part I actually care about: the one real finding (Repo L's signing key) stayed flagged. The test-fixture key with `TEST` as its body got demoted. The noise dropped, the signal didn't. That's the only metric that means anything. Cutting findings is easy if you don't mind going blind; cutting findings while keeping every real one is the whole job.

## The lesson, especially for AI-generated code

The instinct in this space is to add more rules and more detections. The volume of AI-generated code makes that instinct worse, because more code scanned at the same false-positive rate means more noise per real issue, not less. What's actually scarce is the ability to look at a flagged line and decide whether it matters in context. That a localhost string in a test file is fine. That a placeholder in an example env file is fine. That a leaked signing key in a deploy template is very much not fine.

That's the bet behind Critik's two-pass design: cheap regex and AST find candidates, then an LLM reviews each one with surrounding context and votes confirmed, false positive, or needs review. When I ran that second pass over the worst repo, it correctly killed six of seven false positives at high confidence.

It is also not magic, and I'll be honest about where it failed. It confirmed that safe next-themes script as a real XSS in one repo, then correctly called the identical pattern a false positive in another. Same code, two different answers. Context-aware review is better than a raw regex dump, but it has its own variance, and anyone selling you a scanner with a zero false-positive promise is selling you the thing this whole post is about.

If you want to try it on your own code, it's `pip install critik`, and the source is at [github.com/alexlaguardia/critik](https://github.com/alexlaguardia/critik). And if you're shipping AI-generated code: the answer isn't to scan harder, it's to read the findings. Most of them are noise. The one that isn't will be sitting right next to them.

---

## Show HN blurb (separate, for the HN submission)

**Title:** Show HN: I scanned 9 popular AI app templates, 78% of "critical" findings were noise

**Text:**
I run an open-source security scanner (Critik) and pointed it at nine of the most-forked open-source AI app templates. Raw output was ~200 findings, which looks alarming until you read them: test fixtures, .env.example placeholders, feature flags flagged as secrets, framework-standard code flagged as XSS. One finding out of all of them was real (a committed JWT signing key in a self-host deploy template, privately disclosed, name withheld until fixed).

So I used the audit to fix my own tool's precision instead: critical+high findings dropped from 89 to 20 across the same repos, and the one real finding stayed flagged. Writeup covers the specific false-positive patterns, the fixes, and where the AI second-pass still gets it wrong (it confirmed a safe next-themes script as XSS in one repo and correctly dismissed the same pattern in another). Scanner noise, not missed bugs, is why people ignore these tools. Happy to talk through any of it.

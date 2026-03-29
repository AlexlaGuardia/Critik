"""Check explanations — detailed writeups for each security check.

vibecheck explain <check-name> shows:
- What the check detects
- Why it's dangerous
- Real-world example (vulnerable code)
- How to fix it
"""

EXPLANATIONS = {
    "secrets": {
        "title": "Hardcoded Secrets",
        "severity": "CRITICAL",
        "what": "Detects API keys, tokens, passwords, and credentials hardcoded in source files.",
        "why": (
            "Hardcoded secrets get committed to git, pushed to GitHub, and end up in build artifacts. "
            "Bots scrape public repos and exploit leaked keys within minutes. "
            "AWS keys alone cost companies thousands in unauthorized compute."
        ),
        "example": (
            '# Bad\n'
            'OPENAI_KEY = "sk-proj-abc123..."\n'
            'db_url = "postgres://admin:password@prod-db:5432/app"\n'
            '\n'
            '# Good\n'
            'OPENAI_KEY = os.environ["OPENAI_API_KEY"]\n'
            'db_url = os.environ["DATABASE_URL"]'
        ),
        "patterns": [
            "AWS access keys (AKIA...)",
            "GitHub PATs (ghp_...)",
            "OpenAI keys (sk-...T3BlbkFJ...)",
            "Anthropic keys (sk-ant-...)",
            "Stripe live/test keys (sk_live_/sk_test_)",
            "Slack tokens (xoxb-/xoxp-)",
            "Private keys (-----BEGIN PRIVATE KEY-----)",
            "Database URLs with credentials",
            "SendGrid, Telegram, JWT tokens",
            "Generic passwords and API keys",
        ],
    },
    "injection": {
        "title": "Code & SQL Injection",
        "severity": "HIGH",
        "what": "Detects SQL injection, command injection, eval/exec usage, and XSS vectors.",
        "why": (
            "Injection is the #1 web vulnerability (OWASP Top 10). AI coding tools love generating "
            "f-string SQL queries and subprocess calls with shell=True. These patterns let attackers "
            "execute arbitrary code on your server or steal your entire database."
        ),
        "example": (
            '# Bad — SQL injection via f-string\n'
            'db.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
            '\n'
            '# Good — parameterized query\n'
            'db.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
            '\n'
            '# Bad — command injection\n'
            'subprocess.call(f"convert {filename}", shell=True)\n'
            '\n'
            '# Good — no shell\n'
            'subprocess.run(["convert", filename])'
        ),
        "patterns": [
            "SQL via f-string in execute() (Python AST)",
            "SQL via string concatenation in execute()",
            "eval() / exec() usage",
            "os.system() calls",
            "subprocess with shell=True",
            "eval() in JavaScript",
            "dangerouslySetInnerHTML (React XSS)",
            "document.write() (XSS vector)",
        ],
    },
    "auth": {
        "title": "Authentication Issues",
        "severity": "MEDIUM",
        "what": "Detects missing authentication on API routes and endpoints.",
        "why": (
            "Unauthenticated endpoints are the easiest attack surface. AI scaffolding tools often "
            "generate API routes without any auth middleware, leaving mutations (POST/PUT/DELETE) "
            "open to anyone with the URL."
        ),
        "example": (
            '// Bad — no auth check on mutation\n'
            'export async function POST(req) {\n'
            '  const data = await req.json()\n'
            '  await db.insert(data)  // anyone can call this\n'
            '}\n'
            '\n'
            '// Good — verify session first\n'
            'export async function POST(req) {\n'
            '  const session = await getServerSession(authOptions)\n'
            '  if (!session) return Response.json({error: "Unauthorized"}, {status: 401})\n'
            '  // ... proceed\n'
            '}'
        ),
        "patterns": [
            "Next.js API routes with mutations but no auth check",
            "Missing session/token verification keywords",
        ],
    },
    "config": {
        "title": "Insecure Configuration",
        "severity": "MEDIUM",
        "what": "Detects debug mode, insecure cookies, and misconfigured security settings.",
        "why": (
            "Debug mode leaks stack traces, internal paths, and environment variables. "
            "Insecure cookies (missing secure/httpOnly/sameSite) enable session hijacking. "
            "Open CORS allows any website to make authenticated requests to your API."
        ),
        "example": (
            '// Bad\n'
            'NODE_ENV = "development"  // in production config\n'
            'cookie: { secure: false, httpOnly: false }\n'
            'cors: { origin: "*" }\n'
            '\n'
            '// Good\n'
            'NODE_ENV = process.env.NODE_ENV\n'
            'cookie: { secure: true, httpOnly: true, sameSite: "strict" }\n'
            'cors: { origin: "https://myapp.com" }'
        ),
        "patterns": [
            "NODE_ENV hardcoded to development",
            "secure: false on cookies",
            "httpOnly: false on cookies",
            "sameSite: none without secure",
            "CORS origin: * (wildcard)",
            "DEBUG = True in source code",
        ],
    },
    "dotenv-secrets": {
        "title": "Dotenv Exposure",
        "severity": "HIGH",
        "what": "Detects sensitive values in .env files that may be committed to version control.",
        "why": (
            ".env files often contain production secrets. If .gitignore doesn't exclude them "
            "(or if .env.example has real values), secrets end up in git history permanently."
        ),
        "example": (
            '# .env (should be in .gitignore)\n'
            'DATABASE_URL=postgres://admin:realpassword@prod:5432/db\n'
            'STRIPE_SECRET_KEY=sk_live_abc123...\n'
            '\n'
            '# .env.example (safe — use placeholders)\n'
            'DATABASE_URL=postgres://user:password@localhost:5432/db\n'
            'STRIPE_SECRET_KEY=sk_test_your_key_here'
        ),
        "patterns": [
            "Database URLs with credentials in .env",
            "API keys and tokens in .env files",
            "Private keys referenced in .env",
        ],
    },
    "frameworks-supabase": {
        "title": "Supabase Misconfigurations",
        "severity": "CRITICAL",
        "what": "Detects exposed service_role keys, disabled RLS, and hardcoded JWT tokens in Supabase projects.",
        "why": (
            "The Supabase service_role key bypasses ALL Row Level Security. If exposed in client code, "
            "any user can read/write/delete any row in any table. This is the #1 Supabase vulnerability "
            "and AI tools generate it constantly."
        ),
        "example": (
            '// Bad — service_role key in client code\n'
            'const supabase = createClient(url, "eyJhbGc...service_role_key...")\n'
            '\n'
            '// Good — anon key for client, service_role only server-side\n'
            'const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY)\n'
            '\n'
            '// Also check: RLS must be enabled on every table\n'
            '// ALTER TABLE your_table ENABLE ROW LEVEL SECURITY;'
        ),
        "patterns": [
            "service_role key in source code",
            "Hardcoded JWT tokens with createClient",
            "Write operations without RLS/policy mentions",
        ],
    },
    "frameworks-firebase": {
        "title": "Firebase Misconfigurations",
        "severity": "CRITICAL",
        "what": "Detects open Firebase security rules (read/write: true) that allow unrestricted access.",
        "why": (
            "Firebase's default security rules allow anyone to read and write all data. "
            "AI scaffolding tools often copy these defaults without changing them. "
            "This exposes your entire database to the internet."
        ),
        "example": (
            '// Bad — anyone can read/write everything\n'
            '{ "rules": { ".read": true, ".write": true } }\n'
            '\n'
            '// Good — require authentication\n'
            '{ "rules": {\n'
            '  ".read": "auth != null",\n'
            '  ".write": "auth != null && auth.uid == $uid"\n'
            '}}'
        ),
        "patterns": [
            'read: true / write: true in security rules',
            'Firebase API key in client bundles',
        ],
    },
    "frameworks-nextjs": {
        "title": "Next.js / Vercel Misconfigurations",
        "severity": "HIGH",
        "what": "Detects secrets exposed via NEXT_PUBLIC_ prefix and unprotected API routes.",
        "why": (
            "Environment variables prefixed with NEXT_PUBLIC_ are bundled into client JavaScript "
            "and visible to every browser. If you put a secret (API key, database URL) behind "
            "NEXT_PUBLIC_, it's public."
        ),
        "example": (
            '// Bad — secret exposed to browser\n'
            'const key = process.env.NEXT_PUBLIC_SECRET_API_KEY\n'
            'const db = process.env.NEXT_PUBLIC_DATABASE_URL\n'
            '\n'
            '// Good — no NEXT_PUBLIC_ prefix for secrets\n'
            'const key = process.env.SECRET_API_KEY  // server-side only\n'
            'const db = process.env.DATABASE_URL      // server-side only'
        ),
        "patterns": [
            "NEXT_PUBLIC_ prefix on SECRET/PASSWORD/DATABASE/TOKEN vars",
            "API routes with mutations but no auth middleware",
        ],
    },
    "frameworks-nextauth": {
        "title": "NextAuth / Auth.js Misconfigurations",
        "severity": "HIGH",
        "what": "Detects missing NEXTAUTH_SECRET and insecure trustHost settings.",
        "why": (
            "Without NEXTAUTH_SECRET, session tokens are signed with a default key in production, "
            "making them forgeable. trustHost: true skips host header validation, "
            "which is only safe behind a trusted reverse proxy."
        ),
        "example": (
            '// Bad — no secret configured\n'
            'export default NextAuth({ providers: [...] })\n'
            '\n'
            '// Good — explicit secret\n'
            'export default NextAuth({\n'
            '  secret: process.env.NEXTAUTH_SECRET,\n'
            '  providers: [...]\n'
            '})'
        ),
        "patterns": [
            "NextAuth config without secret",
            "trustHost: true without reverse proxy context",
        ],
    },
    "frameworks-prisma": {
        "title": "Prisma ORM Security",
        "severity": "HIGH",
        "what": "Detects unsafe raw SQL queries in Prisma that bypass parameterization.",
        "why": (
            "$queryRawUnsafe and $executeRawUnsafe accept string arguments with no parameterization. "
            "If user input reaches these functions, it's a direct SQL injection vector."
        ),
        "example": (
            '// Bad — no parameterization\n'
            'await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${id}`)\n'
            '\n'
            '// Good — tagged template literal (auto-parameterized)\n'
            'await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`'
        ),
        "patterns": [
            "$queryRawUnsafe() usage",
            "$executeRawUnsafe() usage",
        ],
    },
    "frameworks-stripe": {
        "title": "Stripe Integration Security",
        "severity": "HIGH",
        "what": "Detects Stripe webhook handlers without signature verification.",
        "why": (
            "Without webhook signature verification, anyone can send fake webhook events to your "
            "endpoint — granting free subscriptions, faking payments, or triggering arbitrary logic."
        ),
        "example": (
            '// Bad — no signature verification\n'
            'app.post("/webhook", (req, res) => {\n'
            '  const event = req.body  // trusting unverified payload\n'
            '})\n'
            '\n'
            '// Good — verify signature\n'
            'const event = stripe.webhooks.constructEvent(\n'
            '  req.body, req.headers["stripe-signature"], endpointSecret\n'
            ')'
        ),
        "patterns": [
            "Webhook handler without constructEvent/stripe.webhooks",
        ],
    },
}


def explain_check(name: str) -> str:
    """Return formatted explanation for a check."""
    info = EXPLANATIONS.get(name)

    if not info:
        # Try partial match
        matches = [k for k in EXPLANATIONS if name in k]
        if matches:
            return f"\n  Check '{name}' not found. Did you mean: {', '.join(matches)}?\n"
        available = ", ".join(sorted(EXPLANATIONS.keys()))
        return f"\n  Check '{name}' not found.\n  Available: {available}\n"

    lines = [
        "",
        f"  {info['title']}  [{info['severity']}]",
        f"  {'─' * 50}",
        "",
        f"  {info['what']}",
        "",
        f"  Why it matters:",
        f"  {info['why']}",
        "",
        "  Example:",
    ]

    for code_line in info["example"].split("\n"):
        lines.append(f"    {code_line}")

    lines.append("")
    lines.append("  Patterns detected:")
    for p in info["patterns"]:
        lines.append(f"    - {p}")
    lines.append("")

    return "\n".join(lines)

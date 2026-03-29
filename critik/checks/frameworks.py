"""Framework-specific checks — patterns AI tools commonly misconfigure.

Covers: Supabase, Firebase, Vercel/Next.js, NextAuth/Auth.js, Prisma, Stripe.
These are the exact mistakes vibe-coded apps ship with.
"""

import re
from pathlib import Path

from critik.checks import check
from critik.models import Finding, Severity

# ─── Supabase ────────────────────────────────────────────────────────────────

_SUPABASE_SERVICE_ROLE = re.compile(
    r"(?i)(?:supabase|SUPABASE)[_\s]*(?:service[_\s]*role|SERVICE_ROLE)[_\s]*(?:key|KEY)?\s*[=:]\s*['\"]eyJ"
)
# Also catch: JWT key passed directly as string literal (vibe coders paste keys inline)
_SUPABASE_INLINE_JWT = re.compile(
    r"['\"]eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}['\"]"
)
_SUPABASE_RLS_DISABLED = re.compile(
    r"(?i)\.rpc\s*\(\s*['\"].*['\"]|\.from\s*\(\s*['\"].*['\"]\s*\)\.(?:select|insert|update|delete)\s*\("
)
_SUPABASE_ANON_KEY_SERVER = re.compile(
    r"(?i)(?:createClient|createServerClient)\s*\([^)]*(?:supabase_anon_key|ANON_KEY|anon[_\s]key)"
)


@check(
    name="frameworks-supabase",
    severity="critical",
    languages=["javascript", "typescript"],
    message="Detects Supabase misconfigurations from AI scaffolding",
)
def check_supabase(file_path: Path, content: str, language: str) -> list[Finding]:
    findings = []
    lines = content.split("\n")
    fname = file_path.name.lower()

    # Skip if not a Supabase project
    if "supabase" not in content.lower():
        return findings

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue

        # Service role key via env var name OR JWT pasted inline
        if _SUPABASE_SERVICE_ROLE.search(line):
            findings.append(Finding(
                check_name="supabase-service-role-exposed",
                severity=Severity.CRITICAL,
                file_path=str(file_path),
                line=line_num,
                message="Supabase service_role key in source code — bypasses all RLS",
                snippet=line.rstrip(),
                fix_hint="Service role key must ONLY be used server-side via env var. Use anon key for client code.",
            ))
        elif _SUPABASE_INLINE_JWT.search(line) and "createClient" in content:
            findings.append(Finding(
                check_name="supabase-hardcoded-key",
                severity=Severity.HIGH,
                file_path=str(file_path),
                line=line_num,
                message="Supabase key hardcoded as JWT literal — should be in environment variable",
                snippet=line.rstrip()[:80] + "..." if len(line) > 80 else line.rstrip(),
                fix_hint="Use process.env.SUPABASE_KEY instead of hardcoding the JWT.",
            ))

    # Check for missing RLS hint: if file creates supabase client but never mentions RLS/policy
    if "createClient" in content and "rls" not in content.lower() and "policy" not in content.lower():
        if ".from(" in content and ("insert" in content or "update" in content or "delete" in content):
            findings.append(Finding(
                check_name="supabase-rls-not-mentioned",
                severity=Severity.MEDIUM,
                file_path=str(file_path),
                line=1,
                message="Supabase client performs writes but no RLS/policy references found — verify RLS is enabled",
                snippet="",
                fix_hint="Run: ALTER TABLE your_table ENABLE ROW LEVEL SECURITY; and add policies.",
            ))

    return findings


# ─── Firebase ────────────────────────────────────────────────────────────────

_FIREBASE_OPEN_RULES = re.compile(
    r"""(?:\.?(?:read|write))['"]*\s*:\s*['"]?true['"]?"""
)
_FIREBASE_API_KEY_CLIENT = re.compile(
    r"(?i)(?:firebase|FIREBASE)[_\s]*(?:api[_\s]*key|apiKey)\s*[=:]\s*['\"]AIza[A-Za-z0-9_-]{35}"
)


@check(
    name="frameworks-firebase",
    severity="critical",
    languages=["javascript", "typescript", "json"],
    message="Detects Firebase misconfigurations",
)
def check_firebase(file_path: Path, content: str, language: str) -> list[Finding]:
    findings = []
    lines = content.split("\n")
    fname = file_path.name.lower()

    # Firebase security rules: open read/write
    if "rules" in fname or "firestore" in fname or "database" in fname:
        for line_num, line in enumerate(lines, 1):
            if _FIREBASE_OPEN_RULES.search(line):
                findings.append(Finding(
                    check_name="firebase-open-rules",
                    severity=Severity.CRITICAL,
                    file_path=str(file_path),
                    line=line_num,
                    message="Firebase security rule allows unrestricted access",
                    snippet=line.rstrip(),
                    fix_hint="Replace 'true' with auth-based rules: request.auth != null",
                ))

    return findings


# ─── Next.js / Vercel ────────────────────────────────────────────────────────

_NEXT_PUBLIC_SECRET = re.compile(
    r"(?i)NEXT_PUBLIC_(?:SECRET|PASSWORD|API_SECRET|PRIVATE|TOKEN|DATABASE|SUPABASE_SERVICE)"
)
_SERVER_ACTION_NO_AUTH = re.compile(
    r"['\"]use server['\"]"
)


@check(
    name="frameworks-nextjs",
    severity="high",
    languages=["javascript", "typescript"],
    message="Detects Next.js / Vercel misconfigurations",
)
def check_nextjs(file_path: Path, content: str, language: str) -> list[Finding]:
    findings = []
    lines = content.split("\n")
    fpath = str(file_path).lower()

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue

        # NEXT_PUBLIC_ prefix on secret env vars (exposes to browser)
        match = _NEXT_PUBLIC_SECRET.search(line)
        if match:
            findings.append(Finding(
                check_name="nextjs-public-secret",
                severity=Severity.CRITICAL,
                file_path=str(file_path),
                line=line_num,
                message="Secret exposed to browser via NEXT_PUBLIC_ prefix",
                snippet=line.rstrip(),
                fix_hint="Remove NEXT_PUBLIC_ prefix. Access this variable server-side only.",
            ))

    # API route without auth check
    if "/api/" in fpath and ("route.ts" in fpath or "route.js" in fpath):
        has_auth = any(
            kw in content.lower()
            for kw in ("getserversession", "auth(", "gettoken", "verify", "authenticate",
                        "middleware", "authorization", "currentuser", "getsession")
        )
        has_mutation = any(
            method in content
            for method in ("POST", "PUT", "PATCH", "DELETE")
        )
        if has_mutation and not has_auth:
            findings.append(Finding(
                check_name="nextjs-api-no-auth",
                severity=Severity.MEDIUM,
                file_path=str(file_path),
                line=1,
                message="Next.js API route handles mutations without visible auth check",
                snippet="",
                fix_hint="Add authentication: const session = await getServerSession(authOptions)",
            ))

    return findings


# ─── NextAuth / Auth.js ──────────────────────────────────────────────────────

@check(
    name="frameworks-nextauth",
    severity="high",
    languages=["javascript", "typescript"],
    message="Detects NextAuth/Auth.js misconfigurations",
)
def check_nextauth(file_path: Path, content: str, language: str) -> list[Finding]:
    findings = []
    lines = content.split("\n")

    if "next-auth" not in content and "NextAuth" not in content and "@auth/" not in content:
        return findings

    # Missing NEXTAUTH_SECRET
    if "NEXTAUTH_SECRET" not in content and "secret:" not in content and "secret :" not in content:
        if "NextAuth(" in content or "authOptions" in content.lower():
            findings.append(Finding(
                check_name="nextauth-no-secret",
                severity=Severity.HIGH,
                file_path=str(file_path),
                line=1,
                message="NextAuth config without explicit secret — sessions are insecure in production",
                snippet="",
                fix_hint="Add secret: process.env.NEXTAUTH_SECRET to your NextAuth config",
            ))

    # Callbacks without proper checks
    for line_num, line in enumerate(lines, 1):
        if "trustHost: true" in line or "trustHost:true" in line:
            findings.append(Finding(
                check_name="nextauth-trust-host",
                severity=Severity.MEDIUM,
                file_path=str(file_path),
                line=line_num,
                message="trustHost: true bypasses host header validation — only safe behind a reverse proxy",
                snippet=line.rstrip(),
                fix_hint="Remove trustHost or ensure you're behind a trusted reverse proxy (Vercel, nginx)",
            ))

    return findings


# ─── Prisma ──────────────────────────────────────────────────────────────────

_PRISMA_RAW = re.compile(r"\$(?:queryRaw|executeRaw)\s*`")
_PRISMA_RAW_UNSAFE = re.compile(r"\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(")


@check(
    name="frameworks-prisma",
    severity="high",
    languages=["javascript", "typescript"],
    message="Detects Prisma ORM security issues",
)
def check_prisma(file_path: Path, content: str, language: str) -> list[Finding]:
    findings = []
    lines = content.split("\n")

    if "prisma" not in content.lower():
        return findings

    for line_num, line in enumerate(lines, 1):
        if _PRISMA_RAW_UNSAFE.search(line):
            findings.append(Finding(
                check_name="prisma-raw-unsafe",
                severity=Severity.HIGH,
                file_path=str(file_path),
                line=line_num,
                message="Prisma $queryRawUnsafe/$executeRawUnsafe — no parameterization, SQL injection risk",
                snippet=line.rstrip(),
                fix_hint="Use $queryRaw with tagged template literals: prisma.$queryRaw`SELECT * FROM ... WHERE id = ${id}`",
            ))

    return findings


# ─── Stripe ──────────────────────────────────────────────────────────────────

@check(
    name="frameworks-stripe",
    severity="high",
    languages=["javascript", "typescript"],
    message="Detects Stripe integration issues",
)
def check_stripe(file_path: Path, content: str, language: str) -> list[Finding]:
    findings = []
    lines = content.split("\n")
    fpath = str(file_path).lower()

    if "stripe" not in content.lower():
        return findings

    # Webhook without signature verification
    if "webhook" in fpath or "webhook" in content.lower():
        if "constructEvent" not in content and "stripe.webhooks" not in content:
            if "stripe" in content.lower() and ("POST" in content or "post" in content.lower()):
                findings.append(Finding(
                    check_name="stripe-webhook-no-verify",
                    severity=Severity.HIGH,
                    file_path=str(file_path),
                    line=1,
                    message="Stripe webhook handler without signature verification",
                    snippet="",
                    fix_hint="Use stripe.webhooks.constructEvent(body, sig, endpointSecret) to verify webhook signatures",
                ))

    return findings

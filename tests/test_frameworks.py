"""Tests for framework-specific checks."""

from pathlib import Path
from critik.checks.frameworks import (
    check_supabase, check_firebase, check_nextjs, check_nextauth, check_prisma, check_stripe,
)


# ─── Supabase ────────────────────────────────────────────────────────────────

def test_supabase_hardcoded_jwt():
    code = """
import { createClient } from '@supabase/supabase-js'
const supabase = createClient(url, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake-key-here')
"""
    findings = check_supabase(Path("client.ts"), code, "typescript")
    assert any(f.check_name == "supabase-hardcoded-key" for f in findings)


def test_supabase_rls_warning():
    code = """
import { createClient } from '@supabase/supabase-js'
const supabase = createClient(url, key)
await supabase.from('users').insert({ name: 'test' })
await supabase.from('orders').update({ status: 'paid' })
"""
    findings = check_supabase(Path("app.ts"), code, "typescript")
    assert any(f.check_name == "supabase-rls-not-mentioned" for f in findings)


def test_supabase_clean():
    code = """const x = 1;"""
    findings = check_supabase(Path("test.ts"), code, "typescript")
    assert len(findings) == 0


# ─── Firebase ────────────────────────────────────────────────────────────────

def test_firebase_open_rules():
    code = '{ "rules": {\n  ".read": true,\n  ".write": true\n} }'
    findings = check_firebase(Path("firebase_rules.json"), code, "json")
    assert len(findings) >= 2
    assert all(f.check_name == "firebase-open-rules" for f in findings)


def test_firebase_clean():
    code = """{ "rules": { ".read": "auth != null" } }"""
    findings = check_firebase(Path("firebase_rules.json"), code, "json")
    assert len(findings) == 0


# ─── Next.js ─────────────────────────────────────────────────────────────────

def test_nextjs_public_secret():
    code = """const key = process.env.NEXT_PUBLIC_SECRET_KEY"""
    findings = check_nextjs(Path("page.tsx"), code, "typescript")
    assert any(f.check_name == "nextjs-public-secret" for f in findings)


def test_nextjs_public_database():
    code = """const url = process.env.NEXT_PUBLIC_DATABASE_URL"""
    findings = check_nextjs(Path("config.ts"), code, "typescript")
    assert any(f.check_name == "nextjs-public-secret" for f in findings)


def test_nextjs_api_no_auth():
    code = """
export async function POST(request: Request) {
    const body = await request.json()
    return Response.json({ ok: true })
}
export async function DELETE(request: Request) {
    return Response.json({ ok: true })
}
"""
    findings = check_nextjs(Path("app/api/users/route.ts"), code, "typescript")
    assert any(f.check_name == "nextjs-api-no-auth" for f in findings)


def test_nextjs_api_with_auth():
    code = """
import { getServerSession } from 'next-auth'
export async function POST(request: Request) {
    const session = await getServerSession(authOptions)
    return Response.json({ ok: true })
}
"""
    findings = check_nextjs(Path("app/api/users/route.ts"), code, "typescript")
    assert not any(f.check_name == "nextjs-api-no-auth" for f in findings)


def test_nextjs_public_allowed():
    code = """const url = process.env.NEXT_PUBLIC_APP_URL"""
    findings = check_nextjs(Path("config.ts"), code, "typescript")
    assert len(findings) == 0  # APP_URL is not a secret


# ─── NextAuth ────────────────────────────────────────────────────────────────

def test_nextauth_no_secret():
    code = """
import NextAuth from 'next-auth'
export const authOptions = { providers: [] }
export default NextAuth(authOptions)
"""
    findings = check_nextauth(Path("auth.ts"), code, "typescript")
    assert any(f.check_name == "nextauth-no-secret" for f in findings)


def test_nextauth_trust_host():
    code = """
import NextAuth from 'next-auth'
export default NextAuth({ trustHost: true, providers: [] })
"""
    findings = check_nextauth(Path("auth.ts"), code, "typescript")
    assert any(f.check_name == "nextauth-trust-host" for f in findings)


# ─── Prisma ──────────────────────────────────────────────────────────────────

def test_prisma_raw_unsafe():
    code = """
const result = await prisma.$queryRawUnsafe(sql)
"""
    findings = check_prisma(Path("query.ts"), code, "typescript")
    assert any(f.check_name == "prisma-raw-unsafe" for f in findings)


def test_prisma_safe_query():
    code = """
const result = await prisma.user.findMany({ where: { id: userId } })
"""
    findings = check_prisma(Path("query.ts"), code, "typescript")
    assert len(findings) == 0


# ─── Stripe ──────────────────────────────────────────────────────────────────

def test_stripe_webhook_no_verify():
    code = """
export async function POST(request: Request) {
    const body = await request.json()
    // Process stripe webhook without verification
    await handleStripeEvent(body)
}
"""
    findings = check_stripe(Path("webhook.ts"), code, "typescript")
    assert any(f.check_name == "stripe-webhook-no-verify" for f in findings)


def test_stripe_webhook_with_verify():
    code = """
const event = stripe.webhooks.constructEvent(body, sig, endpointSecret)
"""
    findings = check_stripe(Path("webhook.ts"), code, "typescript")
    assert not any(f.check_name == "stripe-webhook-no-verify" for f in findings)

// Server-side secrets only — no NEXT_PUBLIC_ prefix on anything sensitive. Should NOT flag.
import type { NextApiRequest, NextApiResponse } from "next";

// Server-only env vars (no NEXT_PUBLIC_ prefix) are never bundled to the client.
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;
const DB_URL = process.env.DATABASE_URL;

// NEXT_PUBLIC_ is fine here because it is a genuinely public value, not a secret.
const PUBLIC_ANALYTICS_ID = process.env.NEXT_PUBLIC_ANALYTICS_ID;

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (!STRIPE_SECRET || !DB_URL) {
    return res.status(500).json({ error: "server misconfigured" });
  }
  res.status(200).json({ ok: true, analytics: PUBLIC_ANALYTICS_ID });
}

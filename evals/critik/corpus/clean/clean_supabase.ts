// Supabase client built from env vars — no hardcoded keys. Should NOT flag.
import { createClient } from "@supabase/supabase-js";

const url = process.env.NEXT_PUBLIC_SUPABASE_URL!;
// The anon key is designed to be public; the service-role key stays server-side in env.
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY!;

export const publicClient = createClient(url, anonKey);
export const adminClient = createClient(url, serviceKey);

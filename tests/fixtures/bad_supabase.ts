// Intentionally vulnerable Supabase code for testing
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake-service-role-key'
)

// Direct writes without RLS mention
const { data } = await supabase.from('profiles').insert({ name: 'test' })
const { data: d2 } = await supabase.from('orders').update({ status: 'paid' })

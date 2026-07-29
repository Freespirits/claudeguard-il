import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

// The officially recommended user-scoped client. RLS with auth.uid() is the correct and sufficient
// control for it, so its .eq() calls are not IDOR.
export function db() {
  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    { cookies }
  )
}

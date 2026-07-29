import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

// The officially recommended user-scoped client. Present so the route can authenticate the caller.
export function db() {
  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    { cookies }
  )
}

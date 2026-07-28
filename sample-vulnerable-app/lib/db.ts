// DELIBERATELY INSECURE SAMPLE for testing ClaudeGuardIL.
import { createClient } from '@supabase/supabase-js'

// P0: service_role key exposed to the browser (NEXT_PUBLIC_ prefix) — bypasses all RLS.
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,
)

// P1: hardcoded fallback secret in source.
const FALLBACK_ADMIN_TOKEN = 'sk-proj-EXAMPLE1234567890abcdef1234567890abcdef'
export { FALLBACK_ADMIN_TOKEN }

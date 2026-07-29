import { createClient } from '@supabase/supabase-js'

// Planted: a privileged service-role key behind a NEXT_PUBLIC_ prefix. The bundler substitutes the
// value into client output verbatim, so it ships to every browser.
export const admin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY
)

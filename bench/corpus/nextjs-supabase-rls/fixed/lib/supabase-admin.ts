import { createClient } from '@supabase/supabase-js'

// Fixed: the service-role key has no public prefix and is read only on the server, so it is absent
// from client output.
export const admin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
)

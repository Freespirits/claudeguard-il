import { createEnv } from '@t3-oss/env-nextjs'

// The textbook guard AGAINST leaking server vars into the client bundle. Its runtimeEnv block
// necessarily names every server secret, which is what makes naive readers cry wolf here.
export const env = createEnv({
  server: { STRIPE_SECRET_KEY: z.string(), DATABASE_URL: z.string(), OPENAI_API_KEY: z.string() },
  client: { NEXT_PUBLIC_SUPABASE_URL: z.string(), NEXT_PUBLIC_SUPABASE_ANON_KEY: z.string() },
  runtimeEnv: {
    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,
    DATABASE_URL: process.env.DATABASE_URL,
    OPENAI_API_KEY: process.env.OPENAI_API_KEY,
    NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL,
    NEXT_PUBLIC_SUPABASE_ANON_KEY: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
  },
})

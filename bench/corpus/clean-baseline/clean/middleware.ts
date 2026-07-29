import { createServerClient } from '@supabase/ssr'

export async function middleware(req) {
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    { cookies: req.cookies }
  )
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return Response.redirect(new URL('/login', req.url))
}

export const config = { matcher: ['/api/:path*'] }

import { createServerClient } from '@supabase/ssr'

// The recommended Next pattern: authentication is applied ahead of every /api route, so the
// handlers cannot forget it. The grader still records the routes as `undeterminable` rather than
// `pass` — a matcher existing is not proof that it rejects anonymous callers (LAW 1) — but it
// raises no finding, so nothing unproven is left open and the verdict may be `clean`.
export async function middleware(req) {
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    { cookies: req.cookies })
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return new Response('unauthorized', { status: 401 })
}

export const config = { matcher: ['/api/:path*'] }

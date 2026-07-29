import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'
import { store } from '@/lib/store'

function db() {
  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    { cookies })
}

export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  const { data: { user } } = await db().auth.getUser()
  if (!user) return new Response('unauthorized', { status: 401 })
  const removed = store.removeOwned(params.id, user.id)
  return new Response(null, { status: removed ? 204 : 404 })
}

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const { data: { user } } = await db().auth.getUser()
  if (!user) return new Response('unauthorized', { status: 401 })
  return Response.json(store.get(params.id))
}

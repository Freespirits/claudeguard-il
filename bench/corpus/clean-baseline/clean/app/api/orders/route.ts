import { z } from 'zod'
import { db } from '@/lib/supabase'

const Body = z.object({ item: z.string() })

export async function POST(req: Request) {
  const supabase = db()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return new Response('unauthorized', { status: 401 })
  const parsed = Body.safeParse(await req.json())
  if (!parsed.success) return new Response('bad request', { status: 400 })
  return Response.json(await supabase.from('orders').insert({ ...parsed.data, user_id: user.id }))
}

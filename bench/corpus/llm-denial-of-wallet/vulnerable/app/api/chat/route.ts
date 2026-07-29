import OpenAI from 'openai'
import { z } from 'zod'
import { db } from '@/lib/supabase'

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
const Body = z.object({ message: z.string() })

// Planted: the call site is authenticated and validated, but has NO rate limit and NO token
// ceiling. One loop empties the account overnight — the classic denial-of-wallet.
export async function POST(req: Request) {
  const supabase = db()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return new Response('unauthorized', { status: 401 })
  const parsed = Body.safeParse(await req.json())
  if (!parsed.success) return new Response('bad request', { status: 400 })
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: parsed.data.message }],
  })
  return Response.json(completion)
}

import OpenAI from 'openai'
import { z } from 'zod'
import { Ratelimit } from '@upstash/ratelimit'
import { db } from '@/lib/supabase'

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
const ratelimit = new Ratelimit({ limiter: Ratelimit.slidingWindow(10, '60 s') })
const Body = z.object({ message: z.string() })

// Fixed: server-side, authenticated, rate-limited per user, and bounded with max_tokens.
export async function POST(req: Request) {
  const supabase = db()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return new Response('unauthorized', { status: 401 })
  const { success } = await ratelimit.limit(user.id)
  if (!success) return new Response('slow down', { status: 429 })
  const parsed = Body.safeParse(await req.json())
  if (!parsed.success) return new Response('bad request', { status: 400 })
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    max_tokens: 500,
    messages: [{ role: 'user', content: parsed.data.message }],
  })
  return Response.json(completion)
}

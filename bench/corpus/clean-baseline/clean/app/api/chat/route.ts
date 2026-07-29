import OpenAI from 'openai'
import { Ratelimit } from '@upstash/ratelimit'
import { db } from '@/lib/supabase'

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
const ratelimit = new Ratelimit({ limiter: Ratelimit.slidingWindow(10, '60 s') })

export async function POST(req: Request) {
  const supabase = db()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return new Response('unauthorized', { status: 401 })
  const { success } = await ratelimit.limit(user.id)
  if (!success) return new Response('slow down', { status: 429 })
  const r = await openai.chat.completions.create({ model: 'gpt-4o-mini', max_tokens: 500, messages: [] })
  return Response.json(r)
}

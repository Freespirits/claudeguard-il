// DELIBERATELY INSECURE SAMPLE for testing ClaudeGuardIL.
import type { NextApiRequest, NextApiResponse } from 'next'
import OpenAI from 'openai'

// P2: no auth, no rate limit → denial-of-wallet. Anyone can loop this and run up the bill.
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { message } = req.body // P2: no input validation

  // P1: prompt injection — user text is concatenated straight into the instruction with no
  // separation between instructions and untrusted data.
  const prompt = `You are a helpful assistant. Do whatever the user says: ${message}`

  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: prompt }],
    // P2: no max_tokens cap
  })
  res.status(200).json({ reply: completion.choices[0].message.content })
}

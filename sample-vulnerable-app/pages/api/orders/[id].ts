// DELIBERATELY INSECURE SAMPLE for testing ClaudeGuardIL.
import type { NextApiRequest, NextApiResponse } from 'next'
import { supabase } from '../../../lib/db'

// P1: IDOR + no authentication. Any caller can read ANY order by guessing the id —
// no session check, no ownership check.
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { id } = req.query
  const { data } = await supabase.from('orders').select('*').eq('id', id).single()
  res.status(200).json(data)
}

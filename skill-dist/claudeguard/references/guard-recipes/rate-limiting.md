# Guard: rate limiting

Protect auth endpoints (credential stuffing, OTP bombing) and expensive endpoints (search,
export, **LLM calls** → denial-of-wallet).

## Upstash Ratelimit (serverless-friendly, works on Vercel)

```ts
import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '60 s'),  // 10 requests / minute / key
  prefix: 'rl',
})

export async function POST(req: Request) {
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0] ?? 'anon'
  const { success, reset } = await ratelimit.limit(ip)
  if (!success) {
    return Response.json({ error: 'Too many requests' },
      { status: 429, headers: { 'Retry-After': String(reset) } })
  }
  // ... handle
}
```

Key choice: rate-limit by **user id** when authenticated, by **IP** otherwise. For login, key on
`ip + username` so one attacker can't lock out many accounts *and* can't brute one account.

<a id="llm-endpoints"></a>
## LLM endpoints — layer caps
```ts
// 1) per-user request limit (above)
// 2) hard token cap per call
const completion = await openai.chat.completions.create({
  model, messages, max_tokens: 800,        // bound output cost
})
// 3) per-user daily budget: track spend in Redis/DB, reject over the cap
```

## No external Redis? Options
- A DB-backed counter (`INSERT ... ON CONFLICT` a `(key, window)` row) works for low volume.
- Framework/platform limits: Vercel Firewall rate rules, nginx `limit_req`, Cloudflare rate
  limiting — put a limit at the edge as defense-in-depth.

## Also
- Add lockout/backoff and a captcha after repeated auth failures.
- Return `429` with `Retry-After`; never leak whether the username exists.

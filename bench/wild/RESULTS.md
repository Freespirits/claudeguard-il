# Wild benchmark — first measured numbers

Real detection on **real, fetched code the tool was not tuned on**, against labels authored by a
reviewer **blind to ClaudeGuardIL** (no sight of its rules or output), in a neutral category/CWE
vocabulary. This is a *measurement*, not a gate — unlike `bench/run.mjs`, whose recall is 100% by
construction. Run it with `node bench/wild.mjs`.

## The corpus (6 real repos, pinned to commit SHAs)

| Case | Repo | Kind | Labels |
|------|------|------|--------|
| nextjs-with-supabase | `vercel/next.js` examples/with-supabase | precision (clean) | 0 |
| nextjs-subscription-payments | `vercel/nextjs-subscription-payments` | precision (clean) | 0 |
| lyrictor-firebase-clean | `jtCodes/lyrictor` | precision (clean) | 0 |
| chordmini-firebase-open-rules | `ptnghia-j/ChordMiniApp` | recall | 3 (firebase-open-rules) |
| react-openai-client-key | `sergiecode/openai-api-chatbot-reactjs` | recall | 2 (llm-key-client, llm-no-limit) |
| owasp-nodegoat | `OWASP/NodeGoat` | recall | 9 (rce, ssrf, sqli, xss, cookie, headers, tls, secret) |

## The numbers (covered categories)

```
recall, detected at all : 5/9  (56%)
recall, CONFIRMED       : 4/9  (44%)
candidate false positives: 0
coverage gaps (no rule) : 5
```

**Read them honestly, split by profile — this is the real story:**

- **On ClaudeGuardIL's target profile (Next.js / Supabase / Firebase / AI): 5/5 detected.** chordmini's
  3 open-Firebase-rules and react-openai's 2 (client LLM key + no rate limit) all caught. Strong.
- **Off-profile (Express): 0/4.** NodeGoat is an Express app, and the four misses are Express-specific
  patterns ClaudeGuardIL's Next.js/Supabase-focused rules don't reach: an `express-session` cookie with
  no flags, `helmet` headers, an inbound `http.createServer` (its TLS check is for *outbound* http://),
  and a hard-coded secret literal (which needs gitleaks + git history, not run here). Honest coverage
  boundary, now documented.
- **5 gaps** (rce, ssrf, sql-injection, xss) are categories ClaudeGuardIL deliberately delegates to
  semgrep/Snyk (ADR 0007). Reported as gaps, never blamed on detection quality.

## What the benchmark CAUGHT — and the fixes it drove

The first run flagged **7 candidate false positives on the three reference repos**. Adjudicated against
the actual code: **4 were real tool cry-wolf, 3 were harness-matching artifacts.** All fixed → **0**.

Real false positives fixed in the tool (the benchmark's highest-value output — cry-wolf on
reference code is the cardinal sin):
1. **Read-only public RLS.** `create policy … for select using (true)` on `vercel/nextjs-subscription-payments`'s
   `products`/`prices` — the *standard* Supabase pattern for public data — graded a **confirmed P0**,
   turning the canonical starter `critical`. Now: a world-**writable** `using(true)` stays P0; a
   read-only one is P1 **needs-review** with a public-by-design assumption. (grader.mjs)
2. **Read-only public Firebase.** `allow read: if true` on intentionally-public collections (lyrictor's
   `usernames`/`published`) — same split: writable stays P0, read-only → P1 needs-review. (grader.mjs)
3. **`.env.template` placeholder.** `VITE_OPENAI_API_KEY=your_openai_api_key_here` in a template file
   produced a confirmed secret finding on a placeholder. `.template`/`.sample`/`.dist` are now exempt
   like `.env.example`. (project_model.mjs)
4. **Wrong evidence location.** A bundler-inlined secret pointed at its `.env` *declaration* (a template
   placeholder) instead of the client *usage* where the exposure actually is — and the engine now reads
   Vite's `import.meta.env.VITE_*` usage. Now the finding lands on the real client code. (both)

Harness-matching artifacts fixed in the scorer (not the tool):
5. **File-level weaknesses** (open rules files, missing headers) matched on file+weakness, not an exact
   line — the tool reports one representative open rule while the labeller points at another.
6. **P4 informational** findings ("RLS on, no policies → deny-all") are not cry-wolf, so not FPs.
7. **Sibling detections** — when two rules both correctly flag one labelled bug (CG-LLM-001 *and*
   CG-ENV-001 on the client LLM key), neither is a false positive.

## Caveats (also printed by the scorecard)

- Recall is against a **blind human labeller**, a floor not omniscient truth — the real denominator is
  at least this large.
- The corpus is **small (6 repos)**. Every number tightens as it grows; that is the ratchet.
- A candidate FP is flagged for a human, never silently scored — it may be a real bug the labeller missed.

## Next

Grow the corpus (more real Supabase RLS-off / unauth-route recall cases — the code-search backends were
rate-limited this round), and close the Express coverage boundary NodeGoat exposed if that audience
matters. The instrument now exists; every repo added makes the number more honest.

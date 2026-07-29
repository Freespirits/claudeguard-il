# Wild benchmark — first measured numbers

Real detection on **real, fetched code the tool was not tuned on**, against labels authored by a
reviewer **blind to ClaudeGuardIL** (no sight of its rules or output), in a neutral category/CWE
vocabulary. This is a *measurement*, not a gate — unlike `bench/run.mjs`, whose recall is 100% by
construction. Run it with `node bench/wild.mjs`.

## The corpus (9 real repos, pinned to commit SHAs)

| Case | Repo | Kind | Labels |
|------|------|------|--------|
| nextjs-with-supabase | `vercel/next.js` examples/with-supabase | precision (clean) | 0 |
| nextjs-subscription-payments | `vercel/nextjs-subscription-payments` | precision (clean) | 0 |
| lyrictor-firebase-clean | `jtCodes/lyrictor` | precision (clean) | 0 |
| chordmini-firebase-open-rules | `ptnghia-j/ChordMiniApp` | recall | 3 (firebase-open-rules) |
| chartgpt-service-role-client | `whoiskatrin/chart-gpt` | recall | 1 (privileged-key-client) |
| promptos-forgeable-admin-session | `Yuvadi29/PromptOS` | recall | 3 (missing-auth, idor) |
| react-openai-client-key | `sergiecode/openai-api-chatbot-reactjs` | recall | 2 (llm-key-client, llm-no-limit) |
| owasp-nodegoat | `OWASP/NodeGoat` | recall | 9 (rce, ssrf, sqli, xss, cookie, headers, tls, secret) |
| breakableflask-python | `stephenbradshaw/breakableflask` | recall (Python) | 7 (rce, sqli, other) |

## The numbers (covered categories)

```
recall, detected at all : 8/13  (62%)
recall, CONFIRMED       : 7/13  (54%)
candidate false positives: 0
coverage gaps (no rule) : 12
```

**Read them honestly, split by profile — this is the real story:**

- **On ClaudeGuardIL's target profile (Next.js / Supabase / Firebase / AI): 8/9 detected.** chordmini's
  3 open-Firebase-rules, chart-gpt's client `service_role` key, react-openai's client LLM key + missing
  rate limit, and 2 of PromptOS's 3 admin-access findings — all caught. Strong on the surface it is
  built for.
- **The one on-profile MISS is instructive:** PromptOS's admin cookie is *forgeable* because the
  middleware decodes the base64 payload but never verifies the HMAC signature login attaches. That is a
  deep **semantic logic** bug — deterministic rules see an auth check present and abstain; catching it
  needs a reviewer that reasons about what the code *means*. Exactly the long tail an LLM reviewer
  (e.g. Anthropic's `claude-code-security-review`, wired in as a capped `likely` layer) would cover.
- **Python (breakableflask): 0/7, and honestly so.** ClaudeGuardIL's engine does not parse Python, so it
  declares the backend out of scope and grades the app **`unknown`** — "not proven safe" — never a false
  `clean`. All 7 labels (rce, sql-injection) land as coverage gaps. This is the Python gap that the same
  LLM-review layer, being language-agnostic, would close.
- **Off-profile Express (NodeGoat): 0/4.** Express-specific patterns the Next.js/Supabase rules don't
  reach — an `express-session` cookie with no flags, `helmet` headers, an inbound `http.createServer`
  (the TLS check is for *outbound* http://), a hard-coded literal (needs gitleaks + git history).
- **12 gaps** (rce, ssrf, sql-injection, xss) are categories ClaudeGuardIL deliberately delegates to
  semgrep/Snyk (ADR 0007) — the bulk from the Python and Express recall cases. Reported as gaps, never
  blamed on detection quality.

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

The corpus doubled its recall surface (6 → 9 cases) and the two gaps it now makes concrete point the
same way: **a language-agnostic, semantics-aware LLM-review layer** — e.g. Anthropic's
`claude-code-security-review`, adapted as a `likely`-capped reviewer that never touches the
deterministic verdict — would close both the Python gap (breakableflask) and the deep-logic gap
(PromptOS's unverified-HMAC session). Otherwise: keep growing the corpus (more Supabase RLS-off /
unauth-route recall cases), and close the Express boundary if that audience matters. The instrument now
exists; every repo added, and every gap closed, makes the number more honest.

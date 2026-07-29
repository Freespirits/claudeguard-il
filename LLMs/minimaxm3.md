Strong memo. A few reactions before I guess at what you need:

**What works well**
- The sink-to-source framing is the right call given your constraints (no AST, zero-FP). You're essentially trading completeness for trust.
- Blind spot #3 (env var misuse) is your highest ROI check. It's deterministic, path-based, and the failure mode is invisible to vibecoders. Ship this first.
- Blind spot #2 (unprotected destructive routes) is also nearly free. A regex on `app/api/**/route.ts` checking for absence of `getUser`/`auth`/`session` within N lines is reliable.

**Pushback on two things**

1. **Check #4 (God-Tool)** is fragile. Looking for the literal string `confirm` or `approve` inside the same function will both miss legit checks (e.g., `await requireApproval(toolCall)`) and match bad code (a comment that says `// TODO: confirm with user`). I'd drop the string-matching entirely and instead just *flag all destructive tool names* for human review. The zero-FP mandate makes noisy-but-true better than clever-but-wrong.

2. **Check #3 (RAG Injection)** has a fatal flaw: every production RAG app retrieves user-owned data. If you fire on every Supabase select inside a prompt template, you'll drown the user in noise. The more useful signal is the *opposite direction* — **prompt injection via retrieved content**: a template like `\`Answer based on: ${context}\`` where `context` comes from a user-writable source *and* there's no instruction hierarchy. That's the actual vulnerability, not the retrieval itself.

**One thing missing**
Supply chain. Vibecoders `npm install` aggressively and don't read lockfile diffs. A "did this PR add a dependency with < X downloads / < Y days old / typosquats a popular package" check would catch a huge class of "vibe-installed" malware (we've seen the `chalk-template`, `crossenv.js` style attacks ride exactly this wave).

---

What do you want to do with this — refine the checks, write a detection spec for one of them, prototype the regexes, or something else?
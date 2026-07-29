This is a sharp analysis — the "sink-to-source anchor" framing is exactly the right level of ambition for a zero-FP, no-AST tool. A few reactions, extensions, and one pushback:

---

## On the AI/LLM Checks

**Check #1 (LLM → HTML XSS):** The FP trap you identified (dompurify) is the right one, but there's a subtler variant: the dev who destructures and renames. E.g.:

```js
const { text: sanitized } = DOMPurify.sanitize(llmResponse);
// ... later, in a different scope:
<div dangerouslySetInnerHTML={{ __html: sanitized }} />
```

Your regex would see `llmResponse` → `sanitized` → `dangerouslySetInnerHTML` and fire. The variable name `sanitized` is a strong negative signal you could use. A lightweight "sanitization vocabulary" list (`sanitized`, `clean`, `safe`, `purified`, `escaped`) could suppress the alert when the variable name between the LLM call and the sink contains one of those tokens. Not perfect, but it tilts the precision needle.

**Check #2 (LLM → Exec):** `Function()` is worth adding to the sink list alongside `eval()` — it's the one LLMs frequently suggest as a "safer eval" and it's not. Also, `require()` called with a dynamic string in Node (less common but catastrophic).

**Check #3 (RAG Injection):** This is the hardest to get right without AST. The "owned by current user" FP trap is essentially unsolvable with regex alone. I'd consider scoping this check more narrowly: only flag when the untrusted source is a **query parameter, request body, or URL path** (i.e., `req.query`, `req.body`, `req.params`, `searchParams`, `useSearchParams`, `router.query`). These are unambiguously attacker-controlled. Database-sourced data is too context-dependent for a zero-FP tool.

**Check #5 (Prompt Leakage):** Add `console.error` and logging libraries (`pino`, `winston`, `logger.info`) to the sink list. Also, the `NODE_ENV` guard is often written as:

```js
if (process.env.NODE_ENV !== 'production') console.log(systemPrompt);
```

The negation pattern (`!== 'production'`) is the one to look for as a suppressor.

---

## On the Blind Spots

These three are genuinely excellent and probably higher ROI than some of the LLM checks. A few implementation notes:

**Client-Side Admin Guards:** The cross-file nature of this (frontend `.tsx` vs. backend `api/` route) makes it the hardest to implement. You'd need to correlate two files that share a semantic operation (e.g., a `deleteUser` call in the component and a `DELETE` handler in the API). Without an AST, you're essentially doing string matching across file boundaries. One simplification: flag *any* `if (user.role === 'admin')` in a `.tsx` file as a "review this" nudge, with the caveat that the check can't verify the backend. Still valuable as a prompt for manual review.

**Hidden API Route:** This is straightforward and high-signal. The pattern is: any file in `app/api/` (or `pages/api/`) that contains `DELETE`, `PUT`, `PATCH`, or `POST` method handlers but does *not* contain `auth`, `getUser`, `session`, `requireAuth`, `withAuth`, or `clerk` anywhere in the file. Low FP risk, high impact.

**Client-Side Env Var Misuse:** This is a pure grep and probably the single highest-value check you can add. The pattern: `process.env.` followed by anything that doesn't start with `NEXT_PUBLIC_` (or `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, depending on framework), found in a file outside of `api/`, `server/`, `getServerSideProps`, `getStaticProps`, or Remix `loader`/`action` functions. This catches the exact "I leaked my Stripe secret key into the client bundle" scenario that vibecoders are notorious for.

---

## One More to Consider: The "Placeholder Becomes Real" Pattern

Vibecoders love to scaffold with placeholder values and forget to replace them. A high-signal check:

- Match API keys, tokens, or secrets that match known placeholder patterns: `sk-xxx`, `your-api-key-here`, `changeme`, `test_secret_`, `ghp_xxxxxxxxxxxx`, etc.
- Especially in files that are *not* `.env.example` or documentation.

This is trivial to implement, near-zero FP (who intentionally ships `changeme` as a production secret?), and catches a genuinely common failure mode.

---

## On What Not to Build

Agreed on Electron/Tauri. I'd also add: **supply chain / `package.json` auditing**. Tools like `npm audit`, Snyk, and Socket.dev already own this space with far more data than a regex-based tool could ever have. Don't compete with the network-effect products.

---

## Overall Architecture Thought

Given the cross-file checks you're proposing (especially Blind Spot #1), you might want to consider a two-pass approach:

1. **Pass 1 (per-file):** Run all single-file regex/heuristic checks. Emit findings with file path, line number, and matched content.
2. **Pass 2 (cross-file):** For checks that need correlation (frontend guard vs. backend route), use the output of Pass 1 as input — match "admin guard found in `components/AdminPanel.tsx`" against "no auth check found in `api/admin/` routes."

This keeps the engine stateless per-pass but allows for the richer checks without requiring an AST or full program analysis.

---

What's the output format you're targeting? SARIF, custom JSON, or inline comments? That'll shape how aggressively you can do cross-file correlation.
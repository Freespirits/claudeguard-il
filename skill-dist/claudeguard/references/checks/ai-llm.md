# AI / LLM checks

Vibecoded apps almost always ship an LLM feature (chat, agent, RAG, "ask AI"). These are the
risks specific to that, mapped loosely to the OWASP Top 10 for LLM Applications (LLM01–LLM10).

Contents: [Key exposure](#keys) · [Prompt injection](#pi) · [Indirect/RAG injection](#rag) ·
[Agent tool abuse](#tools) · [Output handling](#output) · [Cost / DoS](#cost) ·
[System-prompt & data leakage](#leak) · [MCP exposure](#mcp)

<a id="keys"></a>
## 1. LLM API key exposure (LLM most-common in the wild)
- **Provider key called from the browser.** `openai`/`anthropic`/`google-generativeai` SDK
  imported in client code, or `fetch('https://api.openai.com', { Authorization: 'Bearer sk-...' })`
  in a component. The key ships to every visitor → they spend your money / use your quota.
  Signal: key shape `sk-`, `sk-ant-`, `AIza`, or provider host in client files, or a
  `NEXT_PUBLIC_*` LLM key. **P0**. Guard: `llm-guardrails.md#server-proxy` (proxy through a
  server route; never expose the key).
- **Key committed / in git history.** Same handling as web secrets — rotate, assume leaked.

<a id="pi"></a>
## 2. Prompt injection (LLM01)
- **User input concatenated into the prompt with no separation.** Attacker text overrides the
  system prompt ("ignore previous instructions..."). Signal: template literals building the
  prompt directly from `req.body`/user message with instructions and data mixed. **P1** (P0 if
  it reaches a privileged tool). Guard: `llm-guardrails.md#instruction-data-separation`.
- **No input constraints** (length, role framing, delimiters). **P2**.
- **Trusting model output as a control decision** (e.g. model says "isAdmin: true" → app grants
  it). **P1**.

<a id="rag"></a>
## 3. Indirect / RAG injection
- **Retrieved documents fed to the model as trusted.** A poisoned web page, PDF, email, or DB
  row can carry instructions the model then follows. Signal: RAG/embeddings pipeline where
  retrieved text is inserted into the prompt with the same trust as the system prompt. **P1**.
  Guard: `llm-guardrails.md#treat-retrieved-as-data`.
- **Tool/agent acting on retrieved content** without a human gate. **P1/P0**.

<a id="tools"></a>
## 4. Agent tool access (excessive agency — LLM06/LLM08)
- **Unbounded tool access.** The agent can call tools that delete data, send email/money, run
  shell, or hit internal APIs, with no allowlist and no scoping. Signal: tool definitions wired
  to destructive actions reachable from user-influenced prompts. **P0/P1**. Guard:
  `llm-guardrails.md#tool-allowlist-and-hitl`.
- **No human-in-the-loop** on irreversible/destructive tools. **P1**.
- **Tools inherit the server's full privileges** (DB admin, service_role, cloud creds). **P0**.
- **No per-tool input validation** (the model chooses arguments freely). **P2**.

<a id="output"></a>
## 5. Insecure output handling (LLM02)
- **Model output rendered as HTML/markdown without sanitizing** → XSS from generated content.
  **P1/P2**. Guard: sanitize + `security-headers.md#csp`.
- **Model output used in SQL/shell/eval.** **P0/P1**.
- **No output filtering** for secrets/PII the model may echo back. **P2**.

<a id="cost"></a>
## 6. Cost / denial-of-wallet (LLM04/LLM10)
- **No rate limit / auth on the LLM endpoint.** Anyone can loop it → huge bill. **P1/P2**.
  Guard: `rate-limiting.md` + auth on the proxy route.
- **No max token / max request caps.** **P2**.
- **No usage caps per user/day.** **P3**.

<a id="leak"></a>
## 7. System-prompt & training-data leakage (LLM07)
- **Secrets embedded in the system prompt** (API keys, internal URLs, business rules that are
  security-relevant). Extractable via prompt injection. **P1/P2**.
- **PII from other users reachable** via shared context / vector store with no tenant isolation.
  **P0/P1**.

<a id="mcp"></a>
## 8. MCP server exposure
- **MCP server reachable without auth**, or exposing tools that touch prod data/creds. **P1**.
- **MCP tool names not scoped** / broad wildcard tool access from an untrusted client. **P2**.

## What to output
For each hit: name the exact tool/route, the untrusted input path, and whether it reaches a
privileged action (that's what turns P2 into P0). Always propose the server-proxy pattern first
when a key is exposed — it's the single most common critical finding in this group.

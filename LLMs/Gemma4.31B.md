## 1. Ranking of Expansion Directions

1. **AI/LLM Depth**: Highest value. This audience is explicitly using AI to build; they are most likely to introduce "AI-native" vulnerabilities that standard scanners miss.
2. **Desktop/Electron**: Medium value. It's a niche subset of the audience, but the "vibecoder" habit of copy-pasting boilerplate leads to dangerous Electron defaults.
3. **Perimeter / DNS Hygiene**: Zero value. This is a white-box source code tool; DNS/SPF/DMARC live in the registrar/DNS provider, not the JS source. It's a different product entirely.

---

## 2. Deep Dive: AI/LLM Depth
Since we have no AST and a zero-FP mandate, we cannot track complex data flow. We must rely on **"Sink-to-Source" anchors**: finding the dangerous function (the sink) and checking if the immediate input is a known LLM response variable.

### Top 5 High-Value Checks

| Check | Detection Heuristic (Regex/Fact) | The FP Trap (Why it might fire on safe code) |
| :--- | :--- | :--- |
| **1. LLM $\rightarrow$ HTML (XSS)** | Match `dangerouslySetInnerHTML` where the `__html` value is a variable that appeared in a previous line as a result of `openai`, `anthropic`, or `langchain` call. | The dev used a sanitization library (e.g., `dompurify`) on the string immediately before the render. |
| **2. LLM $\rightarrow$ Exec (RCE)** | Match `eval()`, `child_process.exec()`, or `vm.runInContext()` where the argument is a variable derived from an LLM completion. | The LLM output is strictly validated against a whitelist/regex (e.g., "only allow 'yes' or 'no'") before execution. |
| **3. RAG Injection (Untrusted $\rightarrow$ Prompt)** | Match a string template literal passed to an LLM client that interpolates a variable sourced from `supabase.from().select()` or `firebase.firestore().get()`. | The data being retrieved is "owned" by the current user (e.g., their own notes), making the "injection" an intended feature. |
| **4. Unprotected "God-Tool"** | Match a tool definition (in a `tools` array) containing `delete`, `update`, `refund`, or `transfer` that is not wrapped in a function containing the string `confirm` or `approve`. | The human-in-the-loop check is handled by a separate UI component/state machine that the engine cannot see. |
| **5. Prompt Leakage (System Prompt)** | Match `console.log` or `res.send` calls that reference the variable containing the `system` prompt or the `system_instruction`. | The log is wrapped in an `if (process.env.NODE_ENV === 'development')` block. |

---

## 3. The Blind Spots (Add These First)

These are "Vibecoder" classics: they trust the frontend to enforce security.

1. **Client-Side "Admin" Guards**: Detect `if (user.role === 'admin')` or similar logic in `.tsx` files that wraps a sensitive UI element, but *no corresponding* check in the `api/` route or Supabase RLS. (Heuristic: "Admin" check in frontend AND "Admin" check ABSENT in backend for the same endpoint).
2. **The "Hidden" API Route**: Detect `api/` routes that perform destructive actions (e.g., `DELETE /api/user`) but lack any authentication middleware or `auth.getUser()` call within the function body.
3. **Client-Side Env Var Misuse**: Detect `process.env.PRIVATE_...` (non-`NEXT_PUBLIC`) being referenced inside a file that is not in the `app/api` or `server` directory. (This catches the "I thought it was secret, but I put it in a component" error).

---

## 4. Not Worth Building

**The Electron/Tauri Frameworks.**
Why? Because the "Vibecoder" persona is almost exclusively shipping web-first, SaaS-style apps (Next.js/Supabase). The overhead of maintaining the "facts" for the Electron IPC bridge and Tauri's Rust-to-JS boundary is high, and the target audience for this tool is likely not shipping desktop apps. If they are, they are using a different boilerplate entirely. Focus on the **LLM attack surface**—it's where the "vibes" meet the "vulnerabilities."
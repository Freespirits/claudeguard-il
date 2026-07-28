# Guard: secrets management

<a id="rotate-and-ignore"></a>
## If a secret leaked: rotate first, then remove

Order matters — deleting the file does **not** un-leak the key.

1. **Rotate/revoke** the key at the provider now (Supabase, OpenAI, Stripe, AWS, …). Assume any
   committed or client-shipped key is already compromised.
2. **Move it server-side.** No `NEXT_PUBLIC_`/`VITE_`/`PUBLIC_` prefix for real secrets.
3. **Ignore and untrack:**
   ```bash
   printf '\n.env\n.env.*\n!.env.example\n*.pem\nserviceAccountKey.json\n' >> .gitignore
   git rm --cached .env .env.local .env.production 2>/dev/null || true
   git commit -m "chore: stop tracking secret files"
   ```
4. **Purge history** if the secret was committed (after rotating):
   ```bash
   # git filter-repo (preferred) — install: pip install git-filter-repo
   git filter-repo --path .env --invert-paths
   # or the BFG: bfg --delete-files .env
   ```
   Then force-push and tell collaborators to re-clone.

## Public vs secret — do not over-flag
- **Public by design (not a finding):** Supabase **anon** key, Firebase `apiKey`, any key
  compiled into a mobile/desktop client (extractable). Protect the *data* (RLS/rules), not the
  identifier.
- **Secret (must be server-side):** Supabase `service_role`, DB URLs with passwords, Stripe/PayPal
  secret keys, LLM provider keys, webhook signing secrets, admin/service-account JSON.

## `.env.example` pattern
Commit a redacted example so teammates know what's needed, never the real values:

```bash
# .env.example  (committed)
SUPABASE_URL=
SUPABASE_SERVICE_ROLE_KEY=      # server only
NEXT_PUBLIC_SUPABASE_ANON_KEY=  # safe to expose
OPENAI_API_KEY=                 # server only
```

## Runtime secrets (Docker/CI)
- Docker: pass at runtime (`--env-file`, Docker/K8s secrets), never `ENV SECRET=` in the image.
- CI: use the platform secret store + OIDC for cloud, never long-lived keys in plaintext YAML.

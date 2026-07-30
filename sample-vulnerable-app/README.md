# ⚠️ DELIBERATELY INSECURE SAMPLE — DO NOT INSTALL, RUN, OR DEPLOY

This directory is a **test fixture** for ClaudeGuardIL, a security scanner for
vibecoded apps. Every vulnerability here is **intentional** and exists so the
scanner can be tested against known-bad input:

- **`.env`** — committed **on purpose** to test the secret scanner. Every value
  is a **fake, non-functional example** (note the `EXAMPLE` markers). Nothing
  here grants access to any real system.
- **`lib/`, `pages/`** — an exposed Supabase `service_role` key behind a
  `NEXT_PUBLIC_` prefix, an IDOR API route, prompt-injection sink.
- **`supabase/`** — tables with no RLS and permissive anon policies.
- **`next.config.js`** — missing security headers.

Details and scope:
[`SECURITY.md`](../SECURITY.md#about-the-deliberately-vulnerable-code-in-this-repo)

If you arrived here via a security scan or an automated classifier: yes, it is
flagged on purpose. It is a fixture, not a deployable application.

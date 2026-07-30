# FIXTURE: unauthenticated-delete (intentionally insecure)

> ⚠️ **Do not install, run, or deploy anything in this directory.**

Ground-truth benchmark case for a security scanner. The `vulnerable/` variant
contains a **deliberate** destructive endpoint without authentication; the
`fixed/` variant remediates it. `expected.json` records what the scanner must
report.

Any credentials, tokens, or keys in this directory are **fake, non-functional
examples**. None grant access to anything.

See [`SECURITY.md`](../../../SECURITY.md#about-the-deliberately-vulnerable-code-in-this-repo).

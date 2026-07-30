# FIXTURE: express-unauthenticated-routes (intentionally insecure)

> ⚠️ **Do not install, run, or deploy anything in this directory.**

Ground-truth benchmark case for a security scanner. The `vulnerable/` variant
contains **deliberate** Express routes missing authentication middleware; the
`fixed/` variant remediates them. `expected.json` records what the scanner must
report.

Any credentials, tokens, or keys in this directory are **fake, non-functional
examples**. None grant access to anything.

See [`SECURITY.md`](../../../SECURITY.md#about-the-deliberately-vulnerable-code-in-this-repo).

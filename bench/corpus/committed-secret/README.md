# FIXTURE: committed-secret (intentionally insecure)

> ⚠️ **Do not install, run, or deploy anything in this directory.**

Ground-truth benchmark case for a security scanner. The `vulnerable/` variant
contains a **deliberate** committed secret; the `fixed/` variant remediates it.
`expected.json` records what the scanner must report.

The secret in this directory is a **fake, non-functional example** crafted to
exercise detection rules. It grants access to nothing.

See [`SECURITY.md`](../../../SECURITY.md#about-the-deliberately-vulnerable-code-in-this-repo).

# bench — benchmark suite (contains intentionally insecure fixtures)

This directory measures ClaudeGuardIL's precision and recall. **Nothing here is
shippable application code.**

- **`corpus/`** — hand-built ground-truth cases. Each is a `vulnerable/` ↔
  `fixed/` pair with an `expected.json` truth file. Every weakness is
  deliberate; every credential is a fake, non-functional example.
- **`wild/`** — real third-party open-source code, vendored at pinned commit
  SHAs and blind-labelled by a reviewer. Deliberately **not** patched — a
  patched case stops measuring anything.
- **`run.mjs`** — runs the corpus benchmark (regression gate).
- **`wild.mjs`** — runs the wild benchmark.

**Do not install, run, or deploy anything under `corpus/` or `wild/`.**

See [`SECURITY.md`](../SECURITY.md#about-the-deliberately-vulnerable-code-in-this-repo)
for the full fixture policy.

# bench/wild — vendored third-party code, pinned, intentionally unpatched

> ⚠️ **Do not install, run, or deploy anything in this directory.**

This directory contains **real third-party open-source projects**, vendored at
pinned commit SHAs and labelled by a reviewer blind to this tool (`wild.mjs`).
Each case's `truth.json` names its `source_url`.

**This is not our code, and it is deliberately not fixed** — a case that got
patched would stop measuring anything. Do **not** bump any manifest here:
changing a version falsifies the corpus rather than tidying it (enforced by
`test/wild_manifest_hygiene.test.mjs`).

Results live in [`RESULTS.md`](RESULTS.md).

See [`SECURITY.md`](../../SECURITY.md#about-the-deliberately-vulnerable-code-in-this-repo)
for the full fixture policy.

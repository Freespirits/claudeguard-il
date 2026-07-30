# FIXTURE: clean-baseline (control case)

> ⚠️ **Do not install, run, or deploy anything in this directory.**

Ground-truth benchmark **control** case for a security scanner. This case
contains no deliberate vulnerability — it is the baseline that must stay clean
so false positives are measurable. `expected.json` records what the scanner
must report (nothing).

Any credential-shaped strings in this directory are **fake, non-functional
examples**. None grant access to anything.

See [`SECURITY.md`](../../../SECURITY.md#about-the-deliberately-vulnerable-code-in-this-repo).

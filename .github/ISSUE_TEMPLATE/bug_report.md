---
name: Bug report
about: The tool missed something it should catch, cried wolf, or misbehaved
title: ''
labels: bug
---

<!-- A security vulnerability IN ClaudeGuardIL itself (e.g. a Tier 1/2 gate bypass)?
     Stop — do not file it publicly. See SECURITY.md instead. -->
<!-- עברית גם בסדר גמור. Hebrew is fine. -->

**What happened** — and what you expected instead. If the tool cried wolf on correct code,
say so plainly: that class of bug is treated as seriously as a missed P0 here.

**The target.** Which fixture tree (`sample-vulnerable-app/`, `bench/corpus/**`,
`bench/wild/*/repo/`) or your own project? Never paste real secrets, `.env` contents, or code you
are not allowed to share — a redacted snippet or a minimal repro beats a full dump.

**Repro.** The exact command (e.g. `node plugin/scripts/grader.mjs <path>`) and the output you got.

**Versions.** The `version` field in `package.json`, `node --version`, OS.

**One honest check.** Does `ERRATA.md` already describe this as a retracted claim?

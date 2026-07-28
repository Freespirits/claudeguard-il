# Contributing to ClaudeGuardIL

Thanks for helping make vibecoded apps safer! ClaudeGuardIL is a **community
project** (not an official Anthropic product) for the
[Israeli Claude community](https://www.facebook.com/groups/cladue). Contributions
in Hebrew or English are equally welcome.

> תרומות בעברית מבורכות. אפשר לפתוח issue או PR בעברית או באנגלית.

## Ways to contribute

- **New security checks** — a pattern the tool should detect.
- **New guard recipes** — a paste-ready fix for a finding.
- **False-positive reports** — a case where the tool cried wolf (very valuable).
- **Translations / wording** — improve the Hebrew or English report text.
- **Bug reports** — something broke or a scanner script misbehaved.

For a **security vulnerability in ClaudeGuardIL itself** (e.g. a way to bypass
the Tier 1/2 authorization gate), do **not** open a public issue — follow
[`SECURITY.md`](SECURITY.md).

## The one rule that matters most: edit `core/`, not the copies

The security knowledge lives **once** in `core/` and is copied into both delivery
wrappers by a build step. So:

- ✅ Edit files under **`core/`** (`core/checks/*`, `core/guard-recipes/*`,
  `core/severity-model.md`, `core/report-template.md`, `core/i18n/*`).
- ❌ Do **not** hand-edit `plugin/skills/claudeguard/references/` or
  `skill-dist/` — those are **generated**. Your changes there will be overwritten.
- After editing `core/`, run the build so both wrappers pick it up:

  ```bash
  node scripts/build.mjs
  ```

  This also re-zips the claude.ai skill and validates its frontmatter.

## How to add a check

1. Open the right catalog in `core/checks/` (e.g. `web.md`, `ai-llm.md`).
2. Add the check with: what it is, how to detect it (a concrete static signal,
   and the preferred scanner if any), a severity per
   [`core/severity-model.md`](core/severity-model.md) (P0–P4), and a pointer to
   the guard recipe that fixes it.
3. If it needs a new fix, add a guard recipe (below).
4. Add a matching case to `sample-vulnerable-app/` so it can be tested, and note
   the expected finding in `examples/sample-report.md`.

## How to add a guard recipe

1. Create or extend a file in `core/guard-recipes/` with a paste-ready, correct
   snippet and a short "how to verify" line.
2. Reference it from the relevant check by its `file#anchor`.
3. Prefer reusing common libraries over introducing new dependencies.

## Bilingual + style rules

- User-facing report text is **Hebrew and English**; code, identifiers, file
  paths, and snippets stay **English**.
- Keep skill bodies **under 500 lines**; keep reference files **one level deep**
  from `SKILL.md`.
- Be honest about confidence. From static signals, say "no RLS policy found for
  table X; confirm with a live check" — not "your database is open."
- Never weaken the Tier 1/2 authorization gate, and never make live/DAST run
  without the `claudeguard.scope.yml` attestations.
- **Never commit real secrets.** The only secret-shaped strings allowed in the
  repo are the fake fixtures in `sample-vulnerable-app/`.

## Testing your change

```bash
# 1. Rebuild both wrappers from core/
node scripts/build.mjs

# 2. Run the scanners against the deliberately-vulnerable sample
node plugin/scripts/run_gitleaks.mjs sample-vulnerable-app
node plugin/scripts/detect_tools.mjs

# 3. (Optional) load the plugin locally and run it end-to-end
claude --plugin-dir ./plugin
#   then, in a project:  /cg-scan
```

If you touched the portable skill, make sure it still validates against the
claude.ai schema (the build step runs `quick_validate.py` when available).

## Submitting a pull request

1. Fork and create a branch (`feat/...`, `fix/...`, `docs/...`).
2. Make focused changes; run the build and tests above.
3. Open a PR and fill in the template. Explain **what** and **why**, and note how
   you tested it.
4. By contributing, you agree your work is released under the repo's **MIT**
   license.

Thank you! 🛡️

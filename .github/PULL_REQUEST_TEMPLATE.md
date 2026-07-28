<!-- Thanks for contributing to ClaudeGuardIL! Please fill this in. HE or EN both fine. -->

## What & why
<!-- What does this change do, and why? Link any related issue (#123). -->


## Type of change
<!-- Put an x in the box(es) that apply. -->
- [ ] New security check
- [ ] New / updated guard recipe
- [ ] False-positive fix (tool over-reported)
- [ ] Bug fix (scanner script / plugin / skill)
- [ ] Docs / translation (Hebrew or English wording)
- [ ] Other:

## How I tested it
<!-- e.g. ran node scripts/build.mjs; ran the scanners against sample-vulnerable-app; loaded via claude --plugin-dir ./plugin and ran /cg-scan -->


## Checklist
- [ ] I edited **`core/`**, not the generated `plugin/skills/claudeguard/references/` or `skill-dist/` copies.
- [ ] I ran `node scripts/build.mjs` so both wrappers are in sync.
- [ ] User-facing text is **bilingual (HE + EN)**; code/identifiers stay English.
- [ ] I did **not** commit any real secret (only fake fixtures under `sample-vulnerable-app/`).
- [ ] I did **not** weaken the Tier 1/2 authorization gate.
- [ ] If I added a check, I added a matching case to `sample-vulnerable-app/` and referenced a guard recipe.
- [ ] The portable skill still validates (build step ran `quick_validate.py` cleanly, if available).

<!-- Security vulnerabilities in ClaudeGuardIL itself: do NOT open a public PR/issue — see SECURITY.md. -->

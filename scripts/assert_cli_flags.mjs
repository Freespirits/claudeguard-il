#!/usr/bin/env node
// SHIP OR DECLARE, turned inward on the grader's own command line.
//
// `methodology/grade-or-declare.md` says an artifact class the engine can discover must either be
// walked by a rule or be declared as an ungraded row, because a class with no rows produces no
// output and a reader cannot tell an unexamined domain from a clean one. The grader's CLI has the
// same failure mode one level up: a flag that no skill teaches and no document mentions is a
// feature nobody can find, and it rots — it keeps parsing, keeps consuming the next argv element,
// and quietly stops matching what the code behind it does. The first person to notice is a user
// whose scan silently ignored the file they passed.
//
// So every flag that CONSUMES A VALUE must be one of:
//   (a) named in at least one `plugin/skills/*\/SKILL.md` — it is shipped, a user can reach it; or
//   (b) listed in `CLI_ONLY_FLAGS` in grader.mjs — it is declared, on the record, with a reason.
// Anything else fails the build.
//
// Zero runtime dependencies (Node builtins only), and no shell globbing — the directory walk is
// explicit so this behaves identically on Linux CI and on a Windows developer machine.
import { readdirSync, readFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { CLI_FLAGS_TAKING_VALUE, CLI_ONLY_FLAGS } from '../plugin/scripts/grader.mjs'

const repo = join(dirname(fileURLToPath(import.meta.url)), '..')
const skillsDir = join(repo, 'plugin', 'skills')

/** Every `--flag` token appearing anywhere in the shipped skills, and which file mentioned it. */
function flagsNamedBySkills() {
  const seen = new Map()
  if (!existsSync(skillsDir)) return seen
  for (const entry of readdirSync(skillsDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    const skillMd = join(skillsDir, entry.name, 'SKILL.md')
    if (!existsSync(skillMd)) continue
    const text = readFileSync(skillMd, 'utf8')
    for (const m of text.matchAll(/--[a-zA-Z][\w-]*/g)) {
      if (!seen.has(m[0])) seen.set(m[0], [])
      const where = seen.get(m[0])
      if (!where.includes(entry.name)) where.push(entry.name)
    }
  }
  return seen
}

const shipped = flagsNamedBySkills()
const errors = []
const rows = []

for (const flag of [...CLI_FLAGS_TAKING_VALUE].sort()) {
  const bySkill = shipped.get(flag)
  if (bySkill) rows.push(`  ${flag.padEnd(16)} shipped   (${bySkill.join(', ')})`)
  else if (CLI_ONLY_FLAGS.has(flag)) rows.push(`  ${flag.padEnd(16)} declared  (CLI_ONLY_FLAGS)`)
  else {
    errors.push(`${flag} takes a value but no plugin/skills/*/SKILL.md names it and it is not in ` +
      'CLI_ONLY_FLAGS. Either teach it in the skill that should be using it, or add it to ' +
      'CLI_ONLY_FLAGS in grader.mjs with a line saying why it stays private.')
  }
}

// Not a failure: `CLI_ONLY_FLAGS` may legitimately declare boolean switches (`--gate`) and flags
// that land on a branch this one has not merged yet. Printed so a stale declaration is at least
// visible rather than accumulating unread.
const notValueTaking = [...CLI_ONLY_FLAGS].filter(f => !CLI_FLAGS_TAKING_VALUE.has(f)).sort()

console.log(`grader CLI — ${CLI_FLAGS_TAKING_VALUE.size} value-taking flag(s), ` +
  `${shipped.size} flag token(s) named across shipped skills:`)
for (const r of rows) console.log(r)
if (notValueTaking.length) {
  console.log(`  (declared but not value-taking: ${notValueTaking.join(', ')} — boolean switches, ` +
    'or flags whose wiring has not landed here yet)')
}

if (errors.length) {
  console.error(`\n✖ ${errors.length} undeclared grader flag(s):`)
  for (const e of errors) console.error('  - ' + e)
  process.exit(1)
}
console.log('ok: every value-taking grader flag is either shipped in a skill or declared CLI-only')

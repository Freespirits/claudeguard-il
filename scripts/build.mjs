#!/usr/bin/env node
// Assemble the shared core/ knowledge into both delivery wrappers, then zip the claude.ai skill.
//   node scripts/build.mjs
// - copies core/ -> plugin/skills/claudeguard/references/  (plugin wrapper)
// - copies core/ -> skill-dist/claudeguard/references/      (claude.ai wrapper)
// - copies the portable SKILL.md into skill-dist/claudeguard/
// - produces claudeguard-skill.zip with SKILL.md at the zip root (claude.ai upload format)
import { cpSync, rmSync, mkdirSync, copyFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { execSync } from 'node:child_process'

const repo = join(dirname(fileURLToPath(import.meta.url)), '..')
const core = join(repo, 'core')
const pluginRefs = join(repo, 'plugin', 'skills', 'claudeguard', 'references')
const distSkill = join(repo, 'skill-dist', 'claudeguard')
const distRefs = join(distSkill, 'references')
const skillMd = join(repo, 'plugin', 'skills', 'claudeguard', 'SKILL.md')

// What from core/ goes into each references/ dir.
const COPY = [
  ['checks', 'dir'],
  ['guard-recipes', 'dir'],
  ['i18n', 'dir'],
  ['authorization', 'dir'],
  ['severity-model.md', 'file'],
  ['report-template.md', 'file'],
]

// Collect failures instead of swallowing them, so the process can exit non-zero at the end.
const errors = []
const fail = msg => { console.error('✖ ' + msg); errors.push(msg) }

function assemble(refDir) {
  rmSync(refDir, { recursive: true, force: true })
  mkdirSync(refDir, { recursive: true })
  for (const [name, kind] of COPY) {
    const src = join(core, name)
    const dst = join(refDir, name)
    if (kind === 'dir') cpSync(src, dst, { recursive: true })
    else copyFileSync(src, dst)
  }
}

console.log('• assembling plugin references…')
assemble(pluginRefs)

console.log('• assembling claude.ai skill references…')
mkdirSync(distSkill, { recursive: true })
assemble(distRefs)
copyFileSync(skillMd, join(distSkill, 'SKILL.md'))

// Zip the claude.ai skill with SKILL.md at the archive root.
const zip = join(repo, 'claudeguard-skill.zip')
try { rmSync(zip, { force: true }) } catch {}
try {
  if (process.platform === 'win32') {
    execSync(
      `powershell -NoProfile -Command "Compress-Archive -Path '${join(distSkill, '*')}' -DestinationPath '${zip}' -Force"`,
      { stdio: 'ignore' })
  } else {
    execSync(`cd "${distSkill}" && zip -r -q "${zip}" .`, { stdio: 'ignore' })
  }
  console.log('• wrote ' + zip)
} catch (e) {
  fail('zip step failed: ' + String(e.message || e).slice(0, 120) +
    '. skill-dist/claudeguard/ is ready to zip manually — put SKILL.md at the archive root.')
}

// Structural check: the claude.ai upload format requires SKILL.md at the archive ROOT, and the
// reference tree must have actually been copied. Silent truncation here ships a skill that
// looks fine and knows nothing.
if (!existsSync(join(distSkill, 'SKILL.md'))) fail('skill-dist/claudeguard/SKILL.md is missing')
for (const [name] of COPY) {
  if (!existsSync(join(distRefs, name))) fail(`reference not assembled: references/${name}`)
}

// Validate the portable skill against the strict claude.ai frontmatter schema when the
// validator is available locally. In --strict (CI), its absence is itself a failure.
const validator = join(process.env.USERPROFILE || process.env.HOME || '', '.claude', 'plugins', 'marketplaces', 'claude-plugins-official', 'plugins', 'skill-creator', 'skills', 'skill-creator', 'scripts', 'quick_validate.py')
if (existsSync(validator)) {
  try {
    // PYTHONUTF8=1: the validator reads files as cp1252 on Windows and crashes on our UTF-8.
    execSync(`python "${validator}" "${distSkill}"`, { stdio: 'inherit', env: { ...process.env, PYTHONUTF8: '1' } })
    console.log('• claude.ai skill validation passed')
  } catch { fail('claude.ai skill validation reported issues (see above)') }
} else {
  console.log('• (optional) skill-creator quick_validate.py not found — skipping frontmatter validation')
}

if (errors.length) {
  console.error(`\n✖ build failed with ${errors.length} error(s):`)
  for (const e of errors) console.error('  - ' + e)
  process.exit(1)   // CI depends on this: previously the build ALWAYS exited 0
}
console.log('done.')

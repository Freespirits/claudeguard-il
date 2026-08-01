#!/usr/bin/env node
// Assemble the shared core/ knowledge into both delivery wrappers, then zip the claude.ai skill.
//   node scripts/build.mjs
// - copies core/ -> plugin/skills/claudeguard/references/  (plugin wrapper)
// - copies core/ -> skill-dist/claudeguard/references/      (claude.ai wrapper)
// - copies the portable SKILL.md into skill-dist/claudeguard/
// - produces claudeguard-skill.zip with SKILL.md at the zip root (claude.ai upload format)
import { cpSync, rmSync, mkdirSync, copyFileSync, existsSync, readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { execSync } from 'node:child_process'
import { zipDir } from './zipdir.mjs'

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
  // The v2 rigour lives in plugin/scripts/, which the claude.ai skill cannot run. methodology/
  // is that method written out for a reader with no interpreter, so both wrappers get it.
  ['methodology', 'dir'],
  // Plain-Hebrew explanations for non-expert vibecoders: a per-finding "in plain words" table
  // (findings.md, keyed by finding id) and a standalone concepts guide. Both wrappers render the
  // per-finding line, so both need the table.
  ['plain-language', 'dir'],
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

// Zip the claude.ai skill with SKILL.md at the archive root. Pure-Node (scripts/zipdir.mjs):
// one code path on every OS, forward-slash entry names guaranteed, byte-reproducible output —
// the old Windows path (PowerShell Compress-Archive) wrote backslash names, which the ZIP spec
// forbids and claude.ai's uploader reads as a flattened tree.
const zip = join(repo, 'claudeguard-skill.zip')
try { rmSync(zip, { force: true }) } catch {}
try {
  zipDir(distSkill, zip)
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

// Guard-link check: every `guard:` citation the grader emits must land on a section that exists.
// That link is the whole payoff of a finding — it is what a panicking non-expert clicks to get
// the paste-ready fix. A dangling one is worse than no link, because it spends the user's trust
// and returns nothing, so it fails the build rather than being reported as a warning.
const graderFile = join(repo, 'plugin', 'scripts', 'grader.mjs')

/** GitHub's heading slug: lowercase, drop punctuation, spaces become dashes. */
const slugify = text => text.trim().toLowerCase()
  .replace(/[^\p{L}\p{N}\s_-]/gu, '')
  .replace(/\s+/g, '-')

/**
 * Every anchor a recipe file offers: explicit `<a id="…">` markers (the house convention, which
 * keeps citations short and stable when a heading is reworded) plus the slug of each heading.
 * Fenced code blocks are stripped first — `# .env.example (committed)` inside a ```bash block is
 * a shell comment, and counting it as a heading would invent anchors that do not exist.
 */
function anchorsOf(markdown) {
  const prose = markdown.replace(/^ {0,3}(```|~~~)[\s\S]*?^ {0,3}\1[^\n]*$/gm, '')
  const anchors = new Set()
  for (const m of prose.matchAll(/<a\s+(?:id|name)\s*=\s*"([^"]+)"/g)) anchors.add(m[1].toLowerCase())
  for (const m of prose.matchAll(/^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$/gm)) anchors.add(slugify(m[1]))
  return anchors
}

if (!existsSync(graderFile)) {
  fail('plugin/scripts/grader.mjs is missing — guard links cannot be checked')
} else {
  const graderSrc = readFileSync(graderFile, 'utf8')
  // Only the literals; `guard: p.guard` is an indirection into a policy table whose own entries
  // are literals and are therefore already collected here.
  const links = [...new Set([...graderSrc.matchAll(/\bguard:\s*'([^']+)'/g)].map(m => m[1]))].sort()
  const anchorCache = new Map()

  let broken = 0
  for (const link of links) {
    const [rel, anchor] = link.split('#')
    if (!rel.startsWith('guard-recipes/')) {
      fail(`guard link "${link}" in grader.mjs does not point into guard-recipes/`)
      broken++
      continue
    }
    const recipe = join(core, rel)
    if (!existsSync(recipe)) {
      fail(`guard link "${link}" in grader.mjs: no such recipe file core/${rel}`)
      broken++
      continue
    }
    if (!anchor) continue // a whole-file citation; the file existing is the whole requirement
    if (!anchorCache.has(recipe)) anchorCache.set(recipe, anchorsOf(readFileSync(recipe, 'utf8')))
    if (!anchorCache.get(recipe).has(anchor.toLowerCase())) {
      fail(`guard link "${link}" in grader.mjs: core/${rel} has no anchor "#${anchor}" ` +
        '(add an `<a id="…"></a>` above the section, or cite the anchor that already exists)')
      broken++
    }
  }
  if (!broken) console.log(`• guard links: ${links.length} unique citation(s), all resolve`)
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

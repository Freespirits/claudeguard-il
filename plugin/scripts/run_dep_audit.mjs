#!/usr/bin/env node
// Dependency vulnerability audit. Detects the ecosystem and runs the matching auditor.
//
// EVERY auditor is normalised to the same shape here:
//   results[] = { ecosystem, tool, vulnerabilities: [{ name, advisorySeverity, via[] }] }
//
// AUDIT FIX C. Before this, only the npm arm was normalised. pnpm, pip-audit and osv-scanner each
// dumped their native JSON into a `raw` key, and the grader — which reads `results[].vulnerabilities`
// — found nothing there. So a pnpm project with twelve critical advisories produced a
// `scan:dependencies` coverage row saying the audit RAN, and zero findings. A tool that reports
// "checked, nothing found" when it did not understand the output is worse than one that does not
// look, because the first answer is trusted.
//
// The normalisers are exported and unit-tested rather than living inside the CLI body, because an
// untested shape-adapter is exactly what failed here: nothing broke loudly, output just went quiet.
//
// `advisorySeverity` is the tool's OWN label, named so it cannot be mistaken for our severity. The
// grader maps it to a P-level and caps confidence, because reachability is unverified.
//
// Usage: node run_dep_audit.mjs [path]
import { execSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

function safeParse(s) { try { return JSON.parse(s) } catch { return null } }

/** Some tools emit one JSON object per line rather than one document. */
export function parseJsonOrNdjson(s) {
  const whole = safeParse(s)
  if (whole) return whole
  const rows = String(s).split(/\r?\n/).map(l => l.trim()).filter(Boolean).map(safeParse).filter(Boolean)
  return rows.length ? rows : null
}

const SEVERITIES = new Set(['critical', 'high', 'moderate', 'medium', 'low', 'info'])
const normSeverity = s => {
  const v = String(s ?? '').toLowerCase()
  if (v === 'medium') return 'moderate' // npm says moderate, OSV and CVSS say medium
  return SEVERITIES.has(v) ? v : 'moderate'
}
const vuln = (name, advisorySeverity, via = []) => ({
  name: String(name),
  advisorySeverity: normSeverity(advisorySeverity),
  via: [...new Set(via.filter(Boolean).map(v => String(v).slice(0, 120)))].slice(0, 4),
})

// THE NORMALISER CONTRACT, and the whole point of this file:
//
//   []    the payload was RECOGNISED and contains zero vulnerabilities
//   null  the payload was NOT recognised — we do not know what it means
//
// Collapsing those two is the defect. `npm audit` in a project with no lockfile returns
// `{"error":{"code":"ENOLOCK"}}`; a normaliser that answered `[]` to that made the adapter report
// "an auditor ran and found nothing", and the grader then recorded the dependency scan as a PASS.
// The check had not run at all. A tool that says "checked, nothing found" when it did not look is
// worse than one that says nothing, because only the first answer is believed.
//
// Lockfile-less projects are not an edge case for this audience — plenty of vibecoded repos
// gitignore the lockfile — so this path is the common one, not the exotic one.

/** A tool's own error envelope. Recognising it is what turns a silent zero into a stated gap. */
function toolError(data) {
  if (!data || Array.isArray(data)) return null
  const e = data.error
  if (!e) return null
  if (typeof e === 'string') return e
  return [e.code, e.summary].filter(Boolean).join(': ') || 'the tool reported an error'
}

// ---- npm ----
//
// Two incompatible shapes across npm major versions. v7+ keys `vulnerabilities` by package name;
// v6 keys `advisories` by advisory id and names the package inside. Reading only one of them meant
// half the Node ecosystem silently produced no findings.
export function normalizeNpm(data) {
  if (!data || toolError(data)) return null
  if (data.vulnerabilities && !Array.isArray(data.vulnerabilities)) {
    return Object.entries(data.vulnerabilities).map(([name, v]) => vuln(
      name, v.severity,
      Array.isArray(v.via) ? v.via.map(x => (typeof x === 'string' ? x : x?.title)) : []))
  }
  if (data.advisories) {
    return Object.values(data.advisories).map(a => vuln(a.module_name, a.severity, [a.title]))
  }
  return null
}

// ---- pnpm ----
//
// `pnpm audit --json` follows npm v6's advisories shape. Newer versions also emit the npm v7+
// shape, so both are handled.
export function normalizePnpm(data) {
  if (!data || toolError(data)) return null
  if (data.advisories) {
    return Object.values(data.advisories).map(a => vuln(
      a.module_name || a.name, a.severity, [a.title]))
  }
  return normalizeNpm(data)
}

// ---- yarn ----
//
// `yarn npm audit --json` (berry) returns the npm shape; classic yarn emits NDJSON where each row
// is `{type: 'auditAdvisory', data: {advisory: {...}}}`.
export function normalizeYarn(parsed) {
  if (!parsed) return null
  if (Array.isArray(parsed)) {
    return parsed
      .filter(r => r?.type === 'auditAdvisory')
      .map(r => r.data?.advisory)
      .filter(Boolean)
      .map(a => vuln(a.module_name, a.severity, [a.title]))
  }
  return normalizeNpm(parsed)
}

// ---- pip-audit ----
//
// Either a bare array of dependencies, or `{dependencies: [...]}`. Advisories carry no severity
// field, so they are reported as `moderate` — the grader caps confidence anyway, and inventing a
// severity the tool never stated would be worse than a neutral one.
export function normalizePipAudit(data) {
  if (toolError(data)) return null
  if (!Array.isArray(data) && !Array.isArray(data?.dependencies)) return null
  const deps = Array.isArray(data) ? data : data.dependencies
  const out = []
  for (const d of deps) {
    for (const v of d.vulns || d.vulnerabilities || []) {
      out.push(vuln(`${d.name}@${d.version ?? '?'}`, v.severity ?? 'moderate',
        [v.id, v.description].filter(Boolean)))
    }
  }
  return out
}

// ---- osv-scanner ----
export function normalizeOsv(data) {
  if (toolError(data) || !Array.isArray(data?.results)) return null
  const out = []
  for (const r of data.results) {
    for (const p of r.packages || []) {
      for (const v of p.vulnerabilities || []) {
        const sev = v.database_specific?.severity
          ?? v.severity?.[0]?.score
          ?? p.groups?.find(g => g.ids?.includes(v.id))?.max_severity
        out.push(vuln(
          `${p.package?.name ?? 'unknown'}@${p.package?.version ?? '?'}`,
          sev, [v.id, v.summary].filter(Boolean)))
      }
    }
  }
  return out
}

// ---- CLI ---------------------------------------------------------------------
//
// Guarded, so importing this module for its normalisers does not shell out to `npm audit`.
const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
if (isMain) {
  const root = process.argv[2] || '.'
  const exists = f => existsSync(join(root, f))

  const has = cmd => {
    try {
      const probe = process.platform === 'win32' ? `where ${cmd}` : `command -v ${cmd}`
      execSync(probe, { stdio: 'ignore' }); return true
    } catch { return false }
  }

  const tryRun = cmd => {
    try {
      return execSync(cmd, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 })
    } catch (e) {
      // audit tools exit non-zero when vulnerabilities are found; stdout is still on e.stdout
      return e.stdout || null
    }
  }

  const results = []
  // Anything we ran but could not understand. Reported so the grader can call the coverage
  // undeterminable rather than clean: an unparsed result is a gap, not an absence of findings.
  const unparsed = []

  const record = (ecosystem, tool, out, normalize) => {
    if (out == null) return
    const parsed = parseJsonOrNdjson(out)
    if (!parsed) {
      unparsed.push({ ecosystem, tool, reason: 'output was not valid JSON', sample: String(out).slice(0, 200) })
      return
    }
    let vulnerabilities
    try { vulnerabilities = normalize(parsed) } catch (e) {
      unparsed.push({ ecosystem, tool, reason: `could not normalize output: ${e.message}` })
      return
    }
    // null means the payload was not recognised — most often the tool's own error envelope. This
    // is the branch that stops "the auditor errored" from being reported as "nothing was found".
    if (vulnerabilities === null) {
      const err = toolError(parsed)
      unparsed.push({
        ecosystem, tool,
        reason: /ENOLOCK|requires an existing lockfile/i.test(err || '')
          ? `${tool} needs a lockfile and this project has none committed, so its dependencies were NOT checked against advisories`
          : err ? `${tool} reported an error instead of results (${err})`
            : `${tool} produced output in a shape this adapter does not recognise`,
      })
      return
    }
    results.push({ ecosystem, tool, vulnerabilities })
  }

  // ---- Node ----
  if (exists('package.json')) {
    if (exists('pnpm-lock.yaml') && has('pnpm')) {
      record('node', 'pnpm', tryRun('pnpm audit --json'), normalizePnpm)
    } else if (exists('yarn.lock') && has('yarn')) {
      record('node', 'yarn', tryRun('yarn npm audit --json') || tryRun('yarn audit --json'), normalizeYarn)
    } else if (has('npm')) {
      record('node', 'npm', tryRun('npm audit --json'), normalizeNpm)
    }
  }

  // ---- Python ----
  if (exists('requirements.txt') || exists('pyproject.toml') || exists('poetry.lock')) {
    if (has('pip-audit')) {
      record('python', 'pip-audit', tryRun('pip-audit -f json'), normalizePipAudit)
    } else {
      unparsed.push({
        ecosystem: 'python', tool: 'none',
        reason: 'no Python dependency auditor is installed, so Python dependencies were NOT checked (pip install pip-audit)',
      })
    }
  }

  // ---- Multi-ecosystem fallback ----
  if (has('osv-scanner') && (results.length === 0 || results.some(r => r.vulnerabilities.length === 0))) {
    record('multi', 'osv-scanner', tryRun(`osv-scanner --format json -r "${root}"`), normalizeOsv)
  }

  console.log(JSON.stringify({
    root,
    // `ran` means an auditor produced output we UNDERSTOOD. A tool that ran and emitted something
    // unparseable must not read as a completed check.
    ran: results.length > 0,
    results,
    unparsed,
    total: results.reduce((n, r) => n + r.vulnerabilities.length, 0),
    note: results.length === 0
      ? 'No dependency auditor available or no manifest found. Fall back to reading the lockfile against known advisories.'
      : 'advisorySeverity is the advisory\'s own label. The grader sets the finding severity and caps confidence at needs-review, because whether the vulnerable code path is reached was not verified.',
  }, null, 2))
}

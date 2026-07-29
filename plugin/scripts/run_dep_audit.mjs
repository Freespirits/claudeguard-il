#!/usr/bin/env node
// Dependency vulnerability audit. Detects the ecosystem and runs the matching auditor.
// Usage: node run_dep_audit.mjs [path]
import { execSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { join } from 'node:path'

const root = process.argv[2] || '.'
const exists = f => existsSync(join(root, f))

function has(cmd) {
  try {
    const probe = process.platform === 'win32' ? `where ${cmd}` : `command -v ${cmd}`
    execSync(probe, { stdio: 'ignore' }); return true
  } catch { return false }
}

function tryRun(cmd) {
  try {
    return execSync(cmd, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 })
  } catch (e) {
    // audit tools exit non-zero when vulns are found; stdout is still on e.stdout
    return e.stdout || null
  }
}

const results = []

// ---- Node ----
if (exists('package.json')) {
  if ((exists('pnpm-lock.yaml') || exists('package.json')) && has('pnpm')) {
    const out = tryRun('pnpm audit --json')
    if (out) results.push({ ecosystem: 'node', tool: 'pnpm', raw: safeParse(out) })
  } else if (has('npm')) {
    const out = tryRun('npm audit --json')
    if (out) {
      const data = safeParse(out)
      const vulns = data?.vulnerabilities || {}
      // `advisorySeverity` is npm's label for the advisory, NOT our finding severity. The grader
      // maps it to a P-level and, crucially, caps confidence at needs-review because reachability
      // is unverified — an unreachable dependency CVE is a known false positive for this audience.
      const summary = Object.entries(vulns).map(([name, v]) => ({
        name, advisorySeverity: v.severity, via: Array.isArray(v.via) ? v.via.map(x => (typeof x === 'string' ? x : x.title)).filter(Boolean) : [],
      }))
      results.push({ ecosystem: 'node', tool: 'npm', metadata: data?.metadata?.vulnerabilities, vulnerabilities: summary })
    }
  }
}

// ---- Python ----
if (exists('requirements.txt') || exists('pyproject.toml') || exists('poetry.lock')) {
  if (has('pip-audit')) {
    const out = tryRun('pip-audit -f json')
    if (out) results.push({ ecosystem: 'python', tool: 'pip-audit', raw: safeParse(out) })
  } else {
    results.push({ ecosystem: 'python', tool: 'none', note: 'pip-audit not installed — pip install pip-audit for Python dep scanning.' })
  }
}

// ---- Multi-ecosystem fallback ----
if (results.length === 0 && has('osv-scanner')) {
  const out = tryRun(`osv-scanner --format json -r "${root}"`)
  if (out) results.push({ ecosystem: 'multi', tool: 'osv-scanner', raw: safeParse(out) })
}

function safeParse(s) { try { return JSON.parse(s) } catch { return { unparsed: String(s).slice(0, 2000) } } }

console.log(JSON.stringify({
  root,
  ran: results.length > 0,
  results,
  note: results.length === 0
    ? 'No dependency auditor available or no manifest found. Fall back to reading the lockfile against known advisories.'
    : 'advisorySeverity is the advisory\'s own label. The grader sets the finding severity and caps confidence at needs-review, because whether the vulnerable code path is reached was not verified.',
}, null, 2))

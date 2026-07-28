#!/usr/bin/env node
// Secret scanning. Uses gitleaks if installed; otherwise a built-in regex/entropy fallback so
// the check always runs. Output: JSON { engine, findings: [{file,line,rule,masked}] }.
// Usage: node run_gitleaks.mjs [path]
import { execSync } from 'node:child_process'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative, extname } from 'node:path'

const root = process.argv[2] || '.'

function hasGitleaks() {
  try {
    const probe = process.platform === 'win32' ? 'where gitleaks' : 'command -v gitleaks'
    execSync(probe, { stdio: 'ignore' }); return true
  } catch { return false }
}

function parseGitleaksRows(out) {
  const rows = JSON.parse(out || '[]')
  return rows.map(r => ({
    file: r.File, line: r.StartLine, rule: r.RuleID, masked: mask(r.Secret || r.Match || ''),
  }))
}

function runGitleaks() {
  try {
    const out = execSync(`gitleaks detect --source "${root}" --no-banner --report-format json --report-path -`,
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 })
    return parseGitleaksRows(out)
  } catch (e) {
    // gitleaks exits with a NON-ZERO code precisely WHEN IT FINDS LEAKS, so execSync throws on
    // the successful-and-interesting path. The results are still on stdout.
    //
    // Previously this returned null, silently fell back to the regex scanner, and STILL reported
    // engine:"gitleaks" — so any repo with real leaks got regex-quality coverage while the report
    // claimed otherwise. A security tool overstating its own coverage is the same betrayal as a
    // false negative.
    const out = e?.stdout
    if (out && String(out).trim()) {
      try { return parseGitleaksRows(String(out)) } catch { /* fall through to real failure */ }
    }
    return null // genuine failure (not installed, bad args, crash) — caller falls back honestly
  }
}

// ---- fallback ----
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'out', 'coverage', 'vendor', '.venv', '__pycache__'])
const TEXT_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.json', '.env', '.yml', '.yaml', '.py', '.rb', '.go', '.java', '.kt', '.swift', '.php', '.sh', '.txt', '.md', '.tf', '.xml', '.properties', '.gradle', ''])
const MAX_FILE = 2 * 1024 * 1024

const RULES = [
  ['openai-key', /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b/],
  ['anthropic-key', /\bsk-ant-[A-Za-z0-9_-]{20,}\b/],
  ['aws-access-key', /\bAKIA[0-9A-Z]{16}\b/],
  ['google-api-key', /\bAIza[0-9A-Za-z\-_]{35}\b/],
  ['slack-token', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  ['github-token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/],
  ['stripe-secret', /\b(sk|rk)_live_[A-Za-z0-9]{20,}\b/],
  ['private-key-block', /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/],
  ['jwt', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
  ['db-url-with-password', /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^:\s]+:[^@\s]+@/],
  ['public-prefixed-secret', /\b(?:NEXT_PUBLIC_|VITE_|PUBLIC_)[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE_KEY|API_KEY|TOKEN|PASSWORD)[A-Z0-9_]*\s*[=:]/],
]

function mask(s) {
  if (!s) return ''
  if (s.length <= 8) return '****'
  return s.slice(0, 4) + '…' + s.slice(-4)
}

function* walk(dir) {
  let entries
  try { entries = readdirSync(dir, { withFileTypes: true }) } catch { return }
  for (const e of entries) {
    if (e.name.startsWith('.') && e.name !== '.env' && !e.name.startsWith('.env')) {
      if (e.isDirectory() && e.name !== '.github') continue
    }
    const full = join(dir, e.name)
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue
      yield* walk(full)
    } else if (e.isFile()) {
      yield full
    }
  }
}

function fallbackScan() {
  const findings = []
  for (const file of walk(root)) {
    const ext = extname(file).toLowerCase()
    const base = file.toLowerCase()
    const isEnv = base.includes('.env')
    if (!TEXT_EXT.has(ext) && !isEnv) continue
    let size
    try { size = statSync(file).size } catch { continue }
    if (size > MAX_FILE) continue
    let text
    try { text = readFileSync(file, 'utf8') } catch { continue }
    const lines = text.split(/\r?\n/)
    for (let i = 0; i < lines.length; i++) {
      for (const [rule, re] of RULES) {
        const m = lines[i].match(re)
        if (m) findings.push({ file: relative(root, file) || file, line: i + 1, rule, masked: mask(m[0]) })
      }
    }
  }
  return findings
}

// Report the engine that ACTUALLY produced the findings, never the one we hoped to use.
const gitleaksAvailable = hasGitleaks()
let findings = gitleaksAvailable ? runGitleaks() : null
const gitleaksSucceeded = findings !== null
if (!gitleaksSucceeded) findings = fallbackScan()

const engine = gitleaksSucceeded ? 'gitleaks' : 'fallback-regex'
const note = gitleaksSucceeded
  ? 'Scanned with gitleaks (includes git history).'
  : gitleaksAvailable
    ? 'gitleaks is installed but failed to run — used built-in patterns instead. Git history was NOT scanned.'
    : 'gitleaks not installed — used built-in patterns. Install gitleaks for git-history + broader coverage.'

console.log(JSON.stringify({
  engine,
  gitleaksAvailable,
  scannedGitHistory: gitleaksSucceeded,
  root,
  count: findings.length,
  findings,
  note,
}, null, 2))

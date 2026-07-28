#!/usr/bin/env node
// SAST via semgrep when installed. If absent, signals the auditor to read the code directly.
// Usage: node run_semgrep.mjs [path]
import { execSync } from 'node:child_process'

const root = process.argv[2] || '.'

function has(cmd) {
  try {
    const probe = process.platform === 'win32' ? `where ${cmd}` : `command -v ${cmd}`
    execSync(probe, { stdio: 'ignore' }); return true
  } catch { return false }
}

if (!has('semgrep')) {
  console.log(JSON.stringify({
    engine: 'none',
    available: false,
    note: 'semgrep not installed — fall back to Claude-native code reading using references/checks/*. To enable: pipx install semgrep (or pip install semgrep).',
  }, null, 2))
  process.exit(0)
}

try {
  const out = execSync(`semgrep --config auto --json --quiet "${root}"`,
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 128 * 1024 * 1024 })
  const data = JSON.parse(out || '{}')
  const findings = (data.results || []).map(r => ({
    file: r.path,
    line: r.start?.line,
    rule: r.check_id,
    severity: r.extra?.severity,
    message: r.extra?.message,
  }))
  console.log(JSON.stringify({ engine: 'semgrep', available: true, count: findings.length, findings }, null, 2))
} catch (e) {
  console.log(JSON.stringify({
    engine: 'semgrep', available: true, error: String(e.message || e).slice(0, 400),
    note: 'semgrep ran but failed or found nothing parseable — fall back to Claude-native reading.',
  }, null, 2))
}

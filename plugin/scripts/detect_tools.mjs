#!/usr/bin/env node
// Reports which security scanners are available so the auditors can choose scanner vs
// Claude-native. Never installs anything. Output: JSON to stdout.
import { execSync } from 'node:child_process'

const TOOLS = [
  'gitleaks', 'trufflehog',            // secrets
  'semgrep',                           // SAST
  'npm', 'pnpm', 'yarn',               // node dep audit
  'pip-audit', 'osv-scanner', 'trivy', // deps / multi
  'checkov', 'tfsec',                  // IaC
]

function has(cmd) {
  try {
    const probe = process.platform === 'win32' ? `where ${cmd}` : `command -v ${cmd}`
    execSync(probe, { stdio: 'ignore' })
    return true
  } catch { return false }
}

const tools = {}
for (const t of TOOLS) tools[t] = has(t)

const summary = {
  secrets: tools.gitleaks || tools.trufflehog,
  sast: tools.semgrep,
  deps: tools.npm || tools.pnpm || tools.yarn || tools['pip-audit'] || tools['osv-scanner'] || tools.trivy,
  iac: tools.checkov || tools.tfsec || tools.trivy,
}

console.log(JSON.stringify({
  platform: process.platform,
  node: process.version,
  tools,
  capabilities: summary,
  note: 'Missing tools are fine — ClaudeGuardIL falls back to reading the code directly. Install only if you want deeper coverage.',
}, null, 2))

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
  'snyk',                              // commercial: SCA reachability, Code dataflow, IaC, container
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

// Being INSTALLED is not the same as being usable. Snyk refuses to scan without a token, so an
// installed-but-unauthenticated CLI would otherwise read as available coverage it cannot deliver.
const snykAuthenticated = !!(process.env.SNYK_TOKEN || '').trim()

const summary = {
  secrets: tools.gitleaks || tools.trufflehog,
  sast: tools.semgrep || (tools.snyk && snykAuthenticated),
  deps: tools.npm || tools.pnpm || tools.yarn || tools['pip-audit'] || tools['osv-scanner'] || tools.trivy,
  iac: tools.checkov || tools.tfsec || tools.trivy || (tools.snyk && snykAuthenticated),
  reachability: tools.snyk && snykAuthenticated,
}

console.log(JSON.stringify({
  platform: process.platform,
  node: process.version,
  tools,
  snyk: {
    installed: tools.snyk,
    authenticated: snykAuthenticated,
    // Snyk Code is the only scan that sends SOURCE off the machine, so it is never implied by the
    // token being present. See run_snyk.mjs and core/methodology/snyk-adapter.md.
    note: tools.snyk && !snykAuthenticated
      ? 'snyk is installed but SNYK_TOKEN is not set, so every Snyk scan would refuse to run — `snyk auth` first.'
      : 'Snyk Code (SAST) uploads source to Snyk\'s cloud and stays off until the user consents explicitly.',
  },
  capabilities: summary,
  note: 'Missing tools are fine — ClaudeGuardIL falls back to reading the code directly. Install only if you want deeper coverage.',
}, null, 2))

#!/usr/bin/env node
// SAST via semgrep when installed. If absent, signals the auditor to read the code directly.
//
// WHY THE CWE PASSTHROUGH EXISTS. ADR 0007 delegates generic dataflow — rce, ssrf, injection-sql,
// xss — to semgrep rather than building `taint.mjs`. But this adapter used to forward only
// {file, line, rule, engineSeverity, message} and DISCARD `extra.metadata.cwe`, so the grader gave
// CG-SAST-001 `cwe: null`. `bench/wild.mjs` matches a finding to a blind label on WEAKNESS and
// PLACE, where weakness is established by category or by CWE — and it calls CWE "the robust
// cross-taxonomy key — both sides speak it". With no CWE, and no `ID_CATEGORY` entry for
// CG-SAST-001, a semgrep hit at exactly the labelled line matched on place and failed on weakness.
// So the delegated arm scored ZERO by construction: every rce/ssrf/sqli/xss label stayed
// `○ GAP — no rule for this category (known)`, which is also the wrong words for a category the ADR
// says we do cover, by delegation. The bridge existed on both sides and nothing connected it.
// Retracted as ERR-008 in ERRATA.md.
//
// So `cwe` is forwarded here as a FACT, in the adapter, exactly like `engineSeverity` — the grader
// still owns the P-level and the confidence (ADR 0001, ADR 0003). Nothing here decides either.
//
// Usage: node run_semgrep.mjs [path]
import { execSync } from 'node:child_process'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * Semgrep writes `metadata.cwe` as either a string or an array of strings, each a full CWE sentence
 * like "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval
 * Injection')". The matcher keys on the bare id, so pull the first `CWE-<n>` out and drop the prose.
 * Returns null when the rule carries no CWE — many semgrep rules don't, and inventing one would be
 * worse than a miss.
 */
export function cweOf(metadata) {
  const raw = metadata?.cwe
  const list = Array.isArray(raw) ? raw : (raw == null ? [] : [raw])
  for (const entry of list) {
    const m = /CWE-(\d+)/i.exec(String(entry))
    if (m) return `CWE-${m[1]}`
  }
  return null
}

/**
 * The same shape problem for OWASP, e.g. "A03:2021 - Injection" or "A1:2017 - Injection".
 * Normalised to the zero-padded `A03:2021` form the grader's own rules already use, so the two are
 * comparable. Null when absent.
 */
export function owaspOf(metadata) {
  const raw = metadata?.owasp
  const list = Array.isArray(raw) ? raw : (raw == null ? [] : [raw])
  for (const entry of list) {
    const m = /A(\d{1,2}):(\d{4})/.exec(String(entry))
    if (m) return `A${m[1].padStart(2, '0')}:${m[2]}`
  }
  return null
}

/**
 * Semgrep's `--json` payload -> the adapter's finding list. Exported so the shape is unit-testable
 * against RECORDED semgrep output rather than a live run: `--config auto` fetches rules from
 * semgrep.dev, so a test that shelled out would be measuring the network.
 */
export function normalizeSemgrep(data) {
  return (data?.results || []).map(r => ({
    // Forward slashes always, to match the engine's paths (see run_gitleaks.mjs).
    file: String(r.path == null ? '' : r.path).split(/[\\/]/).join('/'),
    line: r.start?.line,
    rule: r.check_id,
    // The tool's OWN label, named so it is never mistaken for our severity. The grader owns the
    // P0–P4 mapping; this is only an input to it (Decision 2 — the engine and adapters emit facts).
    engineSeverity: r.extra?.severity,
    message: r.extra?.message,
    // The weakness identity, forwarded verbatim from the rule's metadata. This is what lets a
    // delegated finding be recognised as the same weakness a blind labeller named.
    cwe: cweOf(r.extra?.metadata),
    owasp: owaspOf(r.extra?.metadata),
  }))
}

// ---- CLI ---------------------------------------------------------------------
//
// Guarded, so importing this module for its normalisers does not shell out to `semgrep`
// (the same reason run_dep_audit.mjs guards its own CLI).
const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
if (isMain) {
  const root = process.argv[2] || '.'

  const has = cmd => {
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
    const findings = normalizeSemgrep(data)
    console.log(JSON.stringify({ engine: 'semgrep', available: true, count: findings.length, findings }, null, 2))
  } catch (e) {
    console.log(JSON.stringify({
      engine: 'semgrep', available: true, error: String(e.message || e).slice(0, 400),
      note: 'semgrep ran but failed or found nothing parseable — fall back to Claude-native reading. '
        + '`--config auto` fetches rules from semgrep.dev; on a network that blocks that host, this is the branch you get.',
    }, null, 2))
  }
}

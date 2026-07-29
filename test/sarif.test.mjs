import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { grade } from '../plugin/scripts/grader.mjs'
import { toSarif } from '../plugin/scripts/sarif.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const ENGINE = join(HERE, '..', 'plugin', 'scripts', 'project_model.mjs')
const SARIF_CLI = join(HERE, '..', 'plugin', 'scripts', 'sarif.mjs')

// Build a real model by running the engine on a temp dir, exactly as grader.test.mjs does — SARIF is
// rendered from real grade() output, not from a hand-guessed report shape.
function modelOf(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-sarif-'))
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content, 'utf8')
    }
    return JSON.parse(execFileSync(process.execPath, [ENGINE, dir], {
      encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
    }).replace(/^﻿/, ''))
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

// One fixture that yields findings across BOTH pillars and every confidence tier:
//   security confirmed  — CG-DB-001 (P0), CG-DB-002 (P0), CG-ENV-001 (P0), CG-WEB-010 (P2), CG-WEB-022 (P3)
//   security likely     — CG-WEB-020 (P0)
//   security needs-review — CG-DB-COVERAGE (P0, EMPTY at:[]), CG-WEB-001 x2 (P0 + P1), CG-ENV-002 (P2), CG-WEB-002 (P2)
//   compliance confirmed — CG-A11Y-001 x2 (P1)
// CG-WEB-001 and CG-A11Y-001 each fire on two subjects, which exercises rule-dedup and per-subject
// fingerprints; CG-WEB-001 spans P0/P1, which exercises the rule's worst-case security-severity.
const FILES = {
  'package.json': '{"name":"rich","dependencies":{"next":"15.0.0","openai":"4.0.0","@supabase/supabase-js":"2.0.0","react":"18.2.0"}}',
  'next.config.js': `module.exports = {
  env: { STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY },
  productionBrowserSourceMaps: true,
}`,
  'supabase/migrations/001_orders.sql': 'create table public.orders ( id uuid primary key );',
  'supabase/migrations/002_profiles.sql': `create table public.profiles ( id uuid primary key );
alter table public.profiles enable row level security;
create policy "profiles are readable" on public.profiles for select using (true);`,
  'supabase/migrations/003_invoices.sql': `create table public.invoices ( id uuid primary key, owner uuid );
alter table public.invoices enable row level security;
create policy "own invoices" on public.invoices for select using (auth.uid() = owner);`,
  'lib/ai.ts': 'export const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY',
  'lib/cache.ts': 'export const ck = process.env.NEXT_PUBLIC_CACHE_KEY',
  'lib/admin.ts': `import { createClient } from '@supabase/supabase-js'
export const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
  'app/api/orders/route.ts': 'export async function POST(req){ const body = await req.json(); return Response.json(body) }',
  'app/api/admin/route.ts': `import { admin } from '../../../lib/admin'
export async function POST(req){ return Response.json(await admin.from('x').select()) }`,
  'app/api/me/route.ts': 'export async function GET(){ const u = await getUser(); return Response.json(u) }',
  'components/Ui.tsx': `export function Ui() {
    return (<section>
      <img src="/cat.png" />
      <img src="/dog.png" />
    </section>)
  }`,
}

// The engine is a subprocess; run it once for the whole file.
let MODEL = null
const model = () => (MODEL ??= modelOf(FILES))
const reportOf = () => grade(model(), { allowlist: ['route:app/api/me/route.ts'] })

const keyOf = r => `${r.ruleId}::${r.properties.subject}`
const resultsBy = s => new Map(s.runs[0].results.map(r => [keyOf(r), r]))
const rulesBy = s => new Map(s.runs[0].tool.driver.rules.map(r => [r.id, r]))
const resultsForRule = (s, id) => s.runs[0].results.filter(r => r.ruleId === id)

// A full, schema-valid finding for the synthetic edge-case tests (empty `at`, corroboration, null
// guard) that real grade() output does not conveniently produce.
function mkFinding(over = {}) {
  return {
    id: 'CG-X-001', subject: 'thing:1', title_en: 'A title', title_he: '',
    severity: 'P0', confidence: 'confirmed', provenance: 'rule', pillar: 'security',
    source: null, tier: 'static',
    evidence: { strength: 'definitive', nameOnly: false, why: '', at: [] },
    exploit: 'an exploit', impact: 'an impact', guard: 'guard-recipes/x.md#y',
    cwe: null, owasp: null, autofixable: false, assumption: null, corroboration: [],
    ...over,
  }
}

// ---------------------------------------------------------------------------
// Top-level shape
// ---------------------------------------------------------------------------

test('valid top-level SARIF 2.1.0 shape, with driver name and report-derived version', () => {
  const report = reportOf()
  const s = toSarif(report)
  assert.equal(s.version, '2.1.0')
  assert.equal(s.$schema, 'https://json.schemastore.org/sarif-2.1.0.json')
  assert.ok(Array.isArray(s.runs) && s.runs.length === 1, 'exactly one run')
  const driver = s.runs[0].tool.driver
  assert.equal(driver.name, 'ClaudeGuardIL')
  assert.ok(typeof driver.informationUri === 'string' && /^https?:\/\//.test(driver.informationUri))
  // version comes off the report, not a hardcoded string — tracks package.json without coupling.
  assert.equal(driver.version, report.runRecord.toolVersion)
  assert.ok(Array.isArray(driver.rules) && driver.rules.length > 0)
  assert.ok(Array.isArray(s.runs[0].results) && s.runs[0].results.length === report.findings.length,
    'one result per finding')
})

test('driver.version falls back to a constant when the report has no runRecord.toolVersion', () => {
  const s = toSarif({ findings: [mkFinding()] })
  assert.equal(s.runs[0].tool.driver.version, '0.0.0')
})

// ---------------------------------------------------------------------------
// level ← confidence (NOT severity)
// ---------------------------------------------------------------------------

test('level is mapped by CONFIDENCE: confirmed→error, likely→warning, needs-review→note', () => {
  const report = reportOf()
  const s = toSarif(report)
  const by = resultsBy(s)
  // Spot-check one of each tier against a known subject:
  assert.equal(by.get('CG-DB-001::table:orders').level, 'error', 'definitive→confirmed→error')
  assert.equal(by.get('CG-WEB-020::next-config:next.config.js:env').level, 'warning', 'strong→likely→warning')
  assert.equal(by.get('CG-DB-COVERAGE::database:rls-coverage').level, 'note', 'weak→needs-review→note')
  // ...and prove the whole table holds against the report, so the test tracks the data, not my memory.
  const EXPECT = { confirmed: 'error', likely: 'warning', 'needs-review': 'note' }
  for (const r of s.runs[0].results) {
    const f = report.findings.find(x => x.id === r.ruleId && x.subject === r.properties.subject)
    assert.equal(r.level, EXPECT[f.confidence], `${r.ruleId} ${f.confidence}`)
  }
})

// ---------------------------------------------------------------------------
// Rules: deduped by id, sorted, worst-case severity
// ---------------------------------------------------------------------------

test('rules are deduped by id (and sorted), while every finding still becomes a result', () => {
  const report = reportOf()
  const s = toSarif(report)
  const ids = s.runs[0].tool.driver.rules.map(r => r.id)
  assert.deepEqual(ids, [...new Set(ids)], 'no duplicate rule ids')
  assert.deepEqual(ids, [...ids].sort(), 'rules sorted by id')
  // CG-WEB-001 fires on TWO routes: one rule, two results.
  assert.equal(ids.filter(x => x === 'CG-WEB-001').length, 1)
  assert.equal(resultsForRule(s, 'CG-WEB-001').length, 2)
  // Rule count === distinct finding ids.
  assert.equal(ids.length, new Set(report.findings.map(f => f.id)).size)
})

test('a rule spanning severities advertises its WORST case; each result keeps its own', () => {
  const s = toSarif(reportOf())
  // CG-WEB-001 is P0 on the service-role admin route and P1 on the ordinary orders route.
  assert.equal(rulesBy(s).get('CG-WEB-001').properties['security-severity'], '9.5', 'rule = worst (P0)')
  const perResult = resultsForRule(s, 'CG-WEB-001')
    .map(r => r.properties['security-severity']).sort()
  assert.deepEqual(perResult, ['8.0', '9.5'], 'results keep their own P0 / P1 mapping')
})

// ---------------------------------------------------------------------------
// partialFingerprints — present, stable, distinct per subject
// ---------------------------------------------------------------------------

test('partialFingerprints are present, stable across calls, and differ by subject', () => {
  const report = reportOf()
  const a = toSarif(report)
  const b = toSarif(report)
  for (const r of a.runs[0].results) {
    assert.match(r.partialFingerprints.claudeguardId, /^[0-9a-f]{16}$/, 'sha256 hex, 16 chars')
  }
  // Determinism: byte-identical across two renders of the same report.
  assert.equal(JSON.stringify(a), JSON.stringify(b))
  // Same rule id, different subjects → different fingerprints (so GitHub baselines them separately).
  const web001 = resultsForRule(a, 'CG-WEB-001')
  assert.equal(web001.length, 2)
  assert.notEqual(
    web001[0].partialFingerprints.claudeguardId,
    web001[1].partialFingerprints.claudeguardId)
  // Lock the exact contract: sha256(`${id}::${subject}`), first 16 hex chars.
  const subj = 'route:app/api/admin/route.ts'
  const expect = createHash('sha256').update(`CG-WEB-001::${subj}`).digest('hex').slice(0, 16)
  assert.equal(resultsBy(a).get(`CG-WEB-001::${subj}`).partialFingerprints.claudeguardId, expect)
})

// ---------------------------------------------------------------------------
// A finding with no evidence.at still yields a result
// ---------------------------------------------------------------------------

test('a repo-level finding with empty evidence.at still produces a result, with no locations key', () => {
  const s = toSarif(reportOf())
  // CG-DB-COVERAGE ("RLS state could not be determined") is genuinely location-less: at: [].
  const cov = resultsBy(s).get('CG-DB-COVERAGE::database:rls-coverage')
  assert.ok(cov, 'the repo-level finding must still be a result')
  assert.equal(cov.locations, undefined, 'empty `at` → no locations array (valid SARIF)')
  assert.ok(cov.message.text.length > 0)
})

test('toSarif does not crash on a hand-built finding that has no locations', () => {
  const s = toSarif({ findings: [mkFinding({ subject: 'repo:whole', evidence: { strength: 'weak', nameOnly: false, why: '', at: [] } })] })
  assert.equal(s.runs[0].results.length, 1)
  assert.equal(s.runs[0].results[0].locations, undefined)
})

// ---------------------------------------------------------------------------
// Locations
// ---------------------------------------------------------------------------

test('locations map evidence.at → physicalLocation with a 1-based startLine', () => {
  const report = reportOf()
  const s = toSarif(report)
  const r = resultsBy(s).get('CG-DB-001::table:orders')
  const f = report.findings.find(x => x.id === 'CG-DB-001')
  assert.equal(r.locations[0].physicalLocation.artifactLocation.uri, f.evidence.at[0].file)
  assert.equal(r.locations[0].physicalLocation.region.startLine, f.evidence.at[0].line)
})

test('an evidence.at entry with a null line yields a location with an artifact but no region', () => {
  const s = toSarif(reportOf())
  // CG-WEB-001 on the admin route has at: [{ file, line: null }].
  const r = resultsBy(s).get('CG-WEB-001::route:app/api/admin/route.ts')
  assert.equal(r.locations[0].physicalLocation.artifactLocation.uri, 'app/api/admin/route.ts')
  assert.equal(r.locations[0].physicalLocation.region, undefined, 'no startLine when line is null')
})

// ---------------------------------------------------------------------------
// message.text
// ---------------------------------------------------------------------------

test('message.text is "title_en — exploit", derived from the finding', () => {
  const report = reportOf()
  const s = toSarif(report)
  const f = report.findings.find(x => x.id === 'CG-DB-001')
  const r = resultsBy(s).get('CG-DB-001::table:orders')
  assert.equal(r.message.text, `${f.title_en} — ${f.exploit}`)
})

// ---------------------------------------------------------------------------
// security-severity strings
// ---------------------------------------------------------------------------

test('security-severity strings map P0→9.5 and P2→5.0 on both rule and result', () => {
  const s = toSarif(reportOf())
  const rules = rulesBy(s)
  const by = resultsBy(s)
  // CG-DB-001 (table:orders) is P0.
  assert.equal(by.get('CG-DB-001::table:orders').properties['security-severity'], '9.5')
  assert.equal(rules.get('CG-DB-001').properties['security-severity'], '9.5')
  // CG-WEB-010 (missing security headers) is P2.
  assert.equal(by.get('CG-WEB-010::next-config:next.config.js:headers').properties['security-severity'], '5.0')
  assert.equal(rules.get('CG-WEB-010').properties['security-severity'], '5.0')
})

// ---------------------------------------------------------------------------
// pillar carried into rule AND result properties
// ---------------------------------------------------------------------------

test('pillar is carried into both rule and result properties, so consumers can split the pillars', () => {
  const s = toSarif(reportOf())
  const rules = rulesBy(s)
  const by = resultsBy(s)
  // Compliance (accessibility) pillar.
  assert.equal(by.get('CG-A11Y-001::a11y:components/Ui.tsx:3:img').properties.pillar, 'compliance')
  assert.equal(rules.get('CG-A11Y-001').properties.pillar, 'compliance')
  // Security pillar.
  assert.equal(by.get('CG-DB-001::table:orders').properties.pillar, 'security')
  assert.equal(rules.get('CG-DB-001').properties.pillar, 'security')
  // A downstream consumer can partition security vs compliance purely on the property.
  const compliance = s.runs[0].results.filter(r => r.properties.pillar === 'compliance')
  const security = s.runs[0].results.filter(r => r.properties.pillar === 'security')
  assert.ok(compliance.length >= 2 && security.length >= 1)
})

// ---------------------------------------------------------------------------
// helpUri derived from guard
// ---------------------------------------------------------------------------

test('helpUri is derived from guard: relative by default, absolute with helpUriBase, omitted when null', () => {
  const report = reportOf()
  // Default: the guard path is emitted as a relative help path.
  assert.equal(rulesBy(toSarif(report)).get('CG-DB-001').helpUri, 'guard-recipes/rls-policies.md#enable-rls')
  // With a base, it becomes an absolute URL (what a CI wanting clickable annotations passes).
  const based = rulesBy(toSarif(report, { helpUriBase: 'https://github.com/Freespirits/claudeguard-il/blob/main/core' }))
  assert.equal(based.get('CG-DB-001').helpUri,
    'https://github.com/Freespirits/claudeguard-il/blob/main/core/guard-recipes/rls-policies.md#enable-rls')
  // A finding with no guard omits helpUri entirely (rather than emit a non-URL).
  const noGuard = toSarif({ findings: [mkFinding({ guard: null })] })
  assert.equal(noGuard.runs[0].tool.driver.rules[0].helpUri, undefined)
})

// ---------------------------------------------------------------------------
// relatedLocations from corroboration
// ---------------------------------------------------------------------------

test('relatedLocations are built from corroboration, anchored at the finding location', () => {
  const s = toSarif({
    findings: [mkFinding({
      id: 'CG-DB-004', subject: 'sql-function:public.promote',
      confidence: 'likely', evidence: { strength: 'strong', nameOnly: false, why: 'w', at: [{ file: 'db/f.sql', line: 10, snippet: null }] },
      corroboration: [{ source: 'semgrep', id: 'sql-definer', subject: 'sql-function:public.promote', severity: 'P1', confidence: 'likely', why: 'definer without auth check' }],
    })],
  })
  const r = s.runs[0].results[0]
  assert.equal(r.relatedLocations.length, 1)
  assert.equal(r.relatedLocations[0].physicalLocation.artifactLocation.uri, 'db/f.sql')
  assert.equal(r.relatedLocations[0].physicalLocation.region.startLine, 10)
  assert.match(r.relatedLocations[0].message.text, /semgrep/)
  assert.match(r.relatedLocations[0].message.text, /definer without auth check/)
})

test('no relatedLocations key when there is no corroboration', () => {
  const s = toSarif(reportOf())
  for (const r of s.runs[0].results) assert.equal(r.relatedLocations, undefined)
})

// ---------------------------------------------------------------------------
// Determinism & the opts.now clock hook
// ---------------------------------------------------------------------------

test('output is deterministic and carries no timestamp unless the caller supplies opts.now', () => {
  const report = reportOf()
  assert.equal(JSON.stringify(toSarif(report)), JSON.stringify(toSarif(report)), 'byte-identical')
  assert.equal(toSarif(report).runs[0].invocations, undefined, 'no clock read by default')
  const withNow = toSarif(report, { now: '2026-07-29T00:00:00Z' })
  assert.equal(withNow.runs[0].invocations[0].endTimeUtc, '2026-07-29T00:00:00Z')
})

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

test('CLI reads a graded JSON (BOM-tolerant) and prints a valid SARIF log', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cg-sarif-cli-'))
  try {
    const p = join(dir, 'cg-graded.json')
    // Prepend a BOM exactly like `grader.mjs > cg-graded.json` does under Windows PowerShell.
    writeFileSync(p, '﻿' + JSON.stringify(reportOf()), 'utf8')
    const out = execFileSync(process.execPath, [SARIF_CLI, p], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 })
    const parsed = JSON.parse(out)
    assert.equal(parsed.version, '2.1.0')
    assert.equal(parsed.runs[0].tool.driver.name, 'ClaudeGuardIL')
    assert.ok(parsed.runs[0].results.length > 0)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

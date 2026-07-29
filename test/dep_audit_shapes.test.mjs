import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  normalizeNpm, normalizePnpm, normalizeYarn, normalizePipAudit, normalizeOsv, parseJsonOrNdjson,
} from '../plugin/scripts/run_dep_audit.mjs'
import { grade } from '../plugin/scripts/grader.mjs'

const EMPTY_MODEL = { database: { parserVersion: 2, tables: [] } }

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS — audit fix C.
//
// Only the npm arm of the dependency adapter was ever normalised. pnpm, yarn, pip-audit and
// osv-scanner each dumped their native JSON into a `raw` key, and the grader — which reads
// `results[].vulnerabilities` — found nothing in it. The result was the worst possible output: a
// coverage row stating the dependency audit RAN, and zero findings. "Checked, nothing found" is
// trusted in a way that "not checked" is not, so an unread ecosystem was reported as a clean one.
//
// A shape adapter fails silently by nature — nothing throws, output just goes quiet — which is why
// these are unit tests over recorded tool output rather than an integration run.
// ---------------------------------------------------------------------------

test('npm v7+ keys vulnerabilities by package name', () => {
  const out = normalizeNpm({
    vulnerabilities: {
      lodash: { severity: 'high', via: [{ title: 'Prototype Pollution' }] },
      ws: { severity: 'moderate', via: ['lodash'] },
    },
  })
  assert.deepEqual(out.map(v => v.name).sort(), ['lodash', 'ws'])
  assert.equal(out.find(v => v.name === 'lodash').advisorySeverity, 'high')
  assert.deepEqual(out.find(v => v.name === 'lodash').via, ['Prototype Pollution'])
})

test('npm v6 keys advisories by id and names the package inside', () => {
  // Reading only the v7 shape meant every npm 6 project reported nothing at all.
  const out = normalizeNpm({
    advisories: { 1673: { module_name: 'handlebars', severity: 'critical', title: 'Arbitrary Code Execution' } },
  })
  assert.equal(out.length, 1)
  assert.equal(out[0].name, 'handlebars')
  assert.equal(out[0].advisorySeverity, 'critical')
})

test('pnpm output is understood', () => {
  const out = normalizePnpm({
    advisories: { 1234: { module_name: 'minimist', severity: 'moderate', title: 'Prototype Pollution' } },
  })
  assert.deepEqual(out.map(v => v.name), ['minimist'])
})

test('classic yarn NDJSON is understood', () => {
  // Yarn emits one JSON object per line rather than one document, so a plain JSON.parse returns
  // null and every advisory is lost.
  const raw = [
    JSON.stringify({ type: 'auditAdvisory', data: { advisory: { module_name: 'axios', severity: 'high', title: 'SSRF' } } }),
    JSON.stringify({ type: 'auditSummary', data: { vulnerabilities: { high: 1 } } }),
  ].join('\n')
  const parsed = parseJsonOrNdjson(raw)
  assert.ok(Array.isArray(parsed), 'NDJSON must parse into rows')
  const out = normalizeYarn(parsed)
  assert.deepEqual(out.map(v => v.name), ['axios'])
  assert.equal(out[0].advisorySeverity, 'high')
})

test('pip-audit output is understood, and its missing severity becomes moderate', () => {
  // pip-audit states no severity. Inventing one would be worse than a neutral label, and the
  // grader caps confidence for dependency findings regardless.
  const out = normalizePipAudit({
    dependencies: [{ name: 'jinja2', version: '2.11.2', vulns: [{ id: 'PYSEC-2021-66', description: 'XSS' }] }],
  })
  assert.equal(out.length, 1)
  assert.equal(out[0].name, 'jinja2@2.11.2')
  assert.equal(out[0].advisorySeverity, 'moderate')
})

test('osv-scanner output is understood', () => {
  const out = normalizeOsv({
    results: [{
      packages: [{
        package: { name: 'requests', version: '2.19.1' },
        vulnerabilities: [{ id: 'GHSA-xxxx', summary: 'Header injection', database_specific: { severity: 'MEDIUM' } }],
      }],
    }],
  })
  assert.equal(out.length, 1)
  assert.equal(out[0].name, 'requests@2.19.1')
  // OSV says MEDIUM, npm says moderate. One vocabulary, or the grader's severity table misses.
  assert.equal(out[0].advisorySeverity, 'moderate')
})

test('THE CONTRACT: [] means recognised-and-empty, null means not understood', () => {
  // Collapsing these two is the defect this whole file exists for. `npm audit` in a project with
  // no committed lockfile returns an error envelope; answering [] to that made the adapter report
  // "an auditor ran and found nothing", and the grader recorded the scan as a PASS. Lockfile-less
  // repos are the common case for this audience, not an exotic one.
  assert.equal(normalizeNpm({ error: { code: 'ENOLOCK', summary: 'This command requires an existing lockfile.' } }), null)
  assert.equal(normalizeNpm({ something: 'else' }), null)
  assert.equal(normalizeOsv(null), null)
  assert.equal(normalizePipAudit(undefined), null)

  // ...and a genuinely clean project is still an empty array, not a gap.
  assert.deepEqual(normalizeNpm({ vulnerabilities: {}, metadata: {} }), [])
  assert.deepEqual(normalizeOsv({ results: [] }), [])
  assert.deepEqual(normalizePipAudit({ dependencies: [] }), [])
})

// ---------------------------------------------------------------------------
// The grader side of the same defect.
// ---------------------------------------------------------------------------

test('an auditor whose output could not be read is undeterminable coverage, not a pass', () => {
  // The honest half. If a tool ran and we did not understand it, the ecosystem was NOT checked,
  // and the coverage row has to say so — a gap must be louder than a clean result, not quieter.
  const r = grade(EMPTY_MODEL, {
    scanners: {
      dependencies: {
        ran: true, results: [],
        unparsed: [{ ecosystem: 'node', tool: 'pnpm', reason: 'output was not valid JSON' }],
      },
    },
  })
  const row = r.coverage.scanCoverage.undeterminable.find(s => s.subject === 'scan:dependencies')
  assert.ok(row, 'an unreadable audit result must be a visible coverage hole')
  assert.match(row.note, /could not be read/)
})

test('a lockfile-less project is told WHY its dependencies were not checked', () => {
  // The generic "no auditor was available" sends someone looking for a tool they already have.
  // The adapter knows the real reason, so the coverage row must carry it.
  const r = grade(EMPTY_MODEL, {
    scanners: {
      dependencies: {
        ran: false, results: [],
        unparsed: [{ ecosystem: 'node', tool: 'npm', reason: 'npm needs a lockfile and this project has none committed, so its dependencies were NOT checked against advisories' }],
      },
    },
  })
  const row = r.coverage.scanCoverage.undeterminable.find(s => s.subject === 'scan:dependencies')
  assert.ok(row)
  assert.match(row.note, /lockfile/, 'the actionable reason must survive into the report')
})

test('two advisories for one package do not crash the grade', () => {
  // The subject is the package, so a second advisory collides — and LAW 2 answers a collision with
  // a throw. One package with several CVEs is completely normal input; it must produce a report.
  const r = grade(EMPTY_MODEL, {
    scanners: {
      dependencies: {
        ran: true,
        results: [{ ecosystem: 'node', tool: 'npm', vulnerabilities: [
          { name: 'lodash', advisorySeverity: 'high', via: ['Prototype Pollution'] },
          { name: 'lodash', advisorySeverity: 'moderate', via: ['ReDoS'] },
        ] }],
      },
    },
  })
  assert.equal(r.coverage.dependencies.enumerated, 1)
  const c = r.coverage.dependencies.counts
  assert.equal(c.pass + c.fail + c.undeterminable + c.allowlisted, r.coverage.dependencies.enumerated)
})

test('a normalised pnpm result reaches the grader as a finding', () => {
  // End to end over the shape that used to disappear: adapter output straight into grade().
  const vulnerabilities = normalizePnpm({
    advisories: { 1: { module_name: 'minimist', severity: 'critical', title: 'Prototype Pollution' } },
  })
  const r = grade(EMPTY_MODEL, {
    scanners: { dependencies: { ran: true, results: [{ ecosystem: 'node', tool: 'pnpm', vulnerabilities }] } },
  })
  const f = r.findings.find(x => x.id === 'CG-DEP-001')
  assert.ok(f, 'a pnpm advisory must produce a finding')
  assert.equal(f.confidence, 'needs-review', 'reachability is unverified, so it never reaches the verdict')
})

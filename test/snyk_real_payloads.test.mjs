import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  normalizeSnykSca, normalizeSnykIac, normalizeSnykCode, snykError,
  isCodeDisabledError, isAuthError, failureReason, relativizeObservations,
} from '../plugin/scripts/run_snyk.mjs'
import { grade } from '../plugin/scripts/grader.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const fixture = name => JSON.parse(readFileSync(join(HERE, 'fixtures', 'snyk', name), 'utf8'))

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS, and why it is separate from snyk_adapter.test.mjs.
//
// The adapter was written against shapes inferred from Snyk's documentation. An adapter tested only
// against fixtures its own author invented proves that the author was self-consistent, not that it
// understands the tool — and a shape adapter fails SILENTLY: nothing throws, the output just goes
// quiet. That is exactly how `npm audit`'s no-lockfile error envelope was normalised to `[]` and
// recorded as "checked, nothing found".
//
// Everything in test/fixtures/snyk/ is real output from an authenticated `snyk` v1.1306.2 run
// (org `Freespirits`, free tier). Where a document was large the ARRAY was truncated; every key of
// every retained object is verbatim, because the shape is the whole point.
//
// Four things the real output does that the documentation does not say, each of which the adapter
// would plausibly have got wrong:
//   1. `ok: false` means "vulnerabilities found" on a SUCCESSFUL scan and "the scan failed" on an
//      error. Exit code 1 is a success.
//   2. IaC returns a bare OBJECT for one target and an ARRAY for many. Same command.
//   3. An IaC issue's `path` is an array of resource-graph segments, not a filename.
//   4. Snyk Code is entitlement-gated and reports that as an error string.
// ---------------------------------------------------------------------------

test('REAL: an SCA document with findings is understood', () => {
  const out = normalizeSnykSca(fixture('sca-success.json'))
  assert.ok(Array.isArray(out), 'the real success document must be recognised')
  assert.equal(out.length, 2)
  assert.equal(out[0].kind, 'dep-vuln')
  assert.ok(out[0].advisorySeverity, 'Snyk\'s own severity travels as an INPUT to the grader')
  assert.ok('reachability' in out[0], 'reachability must be present even when unknown')
})

test('REAL: `ok: false` with findings is a SUCCESS, not a failure', () => {
  // The trap. A normalizer keyed on `ok` returns null here and the whole scan disappears; a
  // normalizer keyed on `ok` the other way returns [] for a genuine failure. Neither is right —
  // the discriminator is which key is present.
  const doc = fixture('sca-success.json')
  assert.equal(doc.ok, false, 'the recorded document really does say ok:false while carrying vulns')
  assert.ok(Array.isArray(normalizeSnykSca(doc)), 'and it must still be read as a result')
})

test('REAL: "Missing node_modules" is null, never []', () => {
  // The single most valuable payload in this directory. A vibecoder who cloned a repo and has not
  // run `npm install` gets this EVERY time — it is the common case, not an exotic one. Answering []
  // makes the grader record the dependency scan as a PASS: "checked, nothing found" on a project
  // whose dependencies were never read at all.
  const doc = fixture('sca-no-node-modules.json')
  assert.match(doc.error, /Missing node_modules/)
  assert.equal(normalizeSnykSca(doc), null, 'an unread project must never look like a clean one')
})

test('REAL: an IaC document is a bare OBJECT for one target', () => {
  // Documented nowhere. The same command returns an array for many targets, so a normalizer that
  // assumes one shape silently drops every finding in the other case.
  const doc = fixture('iac-success.json')
  assert.equal(Array.isArray(doc), false, 'one target really is a bare object')
  const out = normalizeSnykIac(doc)
  assert.ok(Array.isArray(out))
  assert.equal(out.length, 6, 'all six recorded issues must survive')
})

test('REAL: the file comes from targetFilePath, because an issue\'s `path` is not a path', () => {
  const doc = fixture('iac-success.json')
  const issue = doc.infrastructureAsCodeIssues[0]
  assert.ok(Array.isArray(issue.path), 'the recorded `path` really is an array of resource segments')
  assert.deepEqual(issue.path.slice(0, 1), ['resource'])

  const out = normalizeSnykIac(doc)
  for (const o of out) {
    assert.match(String(o.at.file), /main\.tf$/,
      'every finding must point at the real file, not at a resource-graph segment')
  }
})

test('REAL: unparseable IaC files produce no findings — Snyk does not read GitHub Actions', () => {
  // Every `.github/workflows/*.yml` in this repo came back `code: 1022, "Failed to parse YAML
  // file"`. Snyk IaC covers Terraform, K8s, CloudFormation and ARM — not Actions. Reporting those
  // as findings would be pure noise, and our own CG-CI-* rules already own that surface.
  const docs = fixture('iac-unparseable.json')
  assert.equal(docs[0].code, 1022)
  const out = normalizeSnykIac(docs)
  assert.ok(out === null || out.length === 0, 'a parse failure is coverage, never a finding')
})

test('REAL: Snyk Code not entitled is a capability gap, not a clean SAST result', () => {
  const doc = fixture('code-not-entitled.json')
  assert.equal(normalizeSnykCode(doc), null)
  assert.equal(isCodeDisabledError(doc.error), true, 'the real message must be recognised verbatim')
  assert.notEqual(isAuthError(doc.error), true,
    'and must not be confused with "you are not logged in" — the fix is completely different')
})

test('REAL: each failure explains itself in words the user can act on', () => {
  const nolock = failureReason(null, fixture('sca-no-node-modules.json').error, 'sca')
  assert.match(String(nolock), /install/i, 'tell them to install, not just that something failed')

  const code = failureReason(null, fixture('code-not-entitled.json').error, 'code')
  assert.match(String(code), /organi[sz]ation|entitle|plan/i,
    'an entitlement limit must be named as one, or the user hunts for a bug that is not there')
})

test('REAL: an unreadable scan becomes an undeterminable coverage row, never a pass', () => {
  // The grader half of the same contract: a tool that ran and was not understood means the
  // ecosystem was NOT checked, and the coverage table has to say so louder than a clean result.
  const r = grade({ database: { parserVersion: 2, tables: [] } }, {
    scanners: {
      dependencies: {
        ran: true, results: [],
        unparsed: [{ ecosystem: 'node', tool: 'snyk', reason: 'snyk needs installed dependencies and this project has none' }],
      },
    },
  })
  const row = r.coverage.scanCoverage.undeterminable.find(s => s.subject === 'scan:dependencies')
  assert.ok(row, 'the gap must be visible')
  assert.match(row.note, /could not be read|dependencies/i)
})

test('REAL: `--all-projects` really does return an array, one document per manifest', () => {
  // Recorded from this repository: 15 documents, one per package.json found. The single-document
  // shape and the array shape come from the same command, so an adapter that assumes one drops
  // everything in the other case.
  const docs = fixture('iac-unparseable.json')
  assert.ok(Array.isArray(docs), 'the multi-target shape is a bare array')
})

test('a PARTIALLY failed run keeps the real results AND stays honest about the rest', () => {
  // The array-level form of the ENOLOCK trap, and the harder one to see: in a monorepo where three
  // of ten packages have no node_modules, Snyk returns seven usable documents and three error
  // documents. Flattening that to "seven results, all clean" reports the three UNREAD packages as
  // clean — the run genuinely succeeded, which is exactly what makes the omission invisible.
  //
  // The contract is a pair: the observations keep the results that are real, and `snykError` marks
  // each failed target so the caller can carry it as a visible limit rather than infer it from
  // silence.
  const mixed = [
    { ok: true, vulnerabilities: [], displayTargetFile: 'packages/a/package.json' },
    { ok: false, error: 'Missing node_modules folder: we can\'t test without dependencies.', path: 'packages/b' },
  ]
  const out = normalizeSnykSca(mixed)
  assert.ok(Array.isArray(out), 'the targets that DID scan must not be thrown away')

  const failed = mixed.filter(d => snykError(d))
  assert.equal(failed.length, 1, 'and the target that did not scan must remain detectable')
  assert.match(String(snykError(failed[0])), /node_modules/,
    'carrying its own reason, so the coverage row can say which package was not checked and why')
})

// ---------------------------------------------------------------------------
// Paths. Snyk reports absolute ones; a report must not.
// ---------------------------------------------------------------------------

test('an absolute path from Snyk is made repo-relative, in the subject as well as the location', () => {
  // A real recorded subject was
  //   snyk:iac-misconfig:C:/Users/hoya2/.../scratchpad/iactest/main.tf:1:SNYK-CC-TF-56
  // Two problems. The report gets SHARED — screenshots, pasted into a group — so it must not carry
  // a username or a local layout. And the subject is what a user ALLOWLISTS and what the
  // benchmark's determinism check compares, so a machine-specific path means the allowlist entry
  // stops matching the moment the same scan runs in CI, and the finding comes back.
  const obs = [{
    subject: 'snyk:iac-misconfig:C:/repo/infra/main.tf:1:SNYK-CC-TF-56',
    at: { file: 'C:/repo/infra/main.tf', line: 1 },
    kind: 'iac-misconfig',
  }]
  const [out] = relativizeObservations(obs, 'C:/repo')
  assert.equal(out.at.file, 'infra/main.tf')
  assert.equal(out.subject, 'snyk:iac-misconfig:infra/main.tf:1:SNYK-CC-TF-56',
    'the subject embeds the path, so both must be rewritten or they disagree')
})

test('relativizing is case-insensitive on the drive letter, and leaves outside paths alone', () => {
  const [inside] = relativizeObservations(
    [{ subject: 's:c:/Repo/a.tf', at: { file: 'C:/Repo/a.tf' } }], 'c:/repo')
  assert.equal(inside.at.file, 'a.tf', 'snyk and node do not always agree on the drive letter case')

  const [outside] = relativizeObservations(
    [{ subject: 's:/elsewhere/a.tf', at: { file: '/elsewhere/a.tf' } }], '/repo')
  assert.equal(outside.at.file, '/elsewhere/a.tf',
    'a path genuinely outside the repo is left intact rather than mangled into a wrong relative one')
})

test('an observation with no file is passed through untouched', () => {
  const obs = [{ subject: 'snyk:dep-vuln:lodash@4.17.11', at: { file: null, line: null } }]
  assert.deepEqual(relativizeObservations(obs, 'C:/repo'), obs)
})

test('REAL: relativizing the recorded IaC output strips the home directory', () => {
  // End to end over the actual recorded document, which really does carry an absolute path through
  // C:/Users/hoya2.
  const doc = fixture('iac-success.json')
  const root = doc.path || doc.targetFilePath.replace(/\/[^/]+$/, '')
  const out = relativizeObservations(normalizeSnykIac(doc), root)
  for (const o of out) {
    assert.ok(!/users\/[^/]+/i.test(o.at.file), `a shared report must not carry a home directory: ${o.at.file}`)
    assert.ok(!/^[a-z]:\//i.test(o.at.file), `nor an absolute drive path: ${o.at.file}`)
    assert.ok(!/users\/[^/]+/i.test(o.subject), `nor may the subject: ${o.subject}`)
  }
})

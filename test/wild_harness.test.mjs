import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  categoryOfFinding, weaknessMatch, findMatch, normFile, fileMatch, COVERED,
} from '../bench/wild.mjs'

// ---------------------------------------------------------------------------
// The wild benchmark's whole value is that its numbers are trustworthy, so the MATCHING logic — which
// decides "did the tool find this independently-labelled bug?" — is unit-tested here. If the matcher
// silently broke, a recall number would be a lie. CWE is the cross-taxonomy bridge; a category maps a
// ClaudeGuardIL id to the neutral label vocabulary. importing bench/wild.mjs must NOT run the
// scorecard (the isMain guard), which this file also implicitly checks by importing cleanly.
// ---------------------------------------------------------------------------

test('categoryOfFinding maps ClaudeGuardIL ids to the neutral vocabulary', () => {
  assert.equal(categoryOfFinding('CG-WEB-001'), 'missing-auth')
  assert.equal(categoryOfFinding('CG-FB-003'), 'firebase-open-rules')
  assert.equal(categoryOfFinding('CG-DB-001'), 'rls-disabled')
  assert.equal(categoryOfFinding('CG-PRIV-TLS'), 'cleartext-transit')
  assert.equal(categoryOfFinding('CG-A11Y-001'), null, 'compliance ids are not security categories')
  assert.equal(categoryOfFinding('CG-UNKNOWN-999'), null)
})

test('normFile strips the repo/ prefix and normalises slashes', () => {
  assert.equal(normFile('repo/app/api/x/route.ts'), 'app/api/x/route.ts')
  assert.equal(normFile('repo\\app\\x.ts'), 'app/x.ts')
  assert.equal(normFile(null), '')
})

test('fileMatch is exact-or-basename', () => {
  assert.ok(fileMatch('app/api/x/route.ts', 'app/api/x/route.ts'))
  assert.ok(fileMatch('app/api/x/route.ts', 'a/b/route.ts'), 'basename fallback for depth drift')
  assert.equal(fileMatch('app/x.ts', 'app/y.ts'), false)
})

test('weaknessMatch: agree via category OR via CWE', () => {
  const label = { category: 'missing-auth', cwe: 'CWE-306' }
  assert.ok(weaknessMatch(label, { category: 'missing-auth', cwe: null }), 'same category')
  assert.ok(weaknessMatch(label, { category: null, cwe: 'CWE-306' }), 'same CWE bridges taxonomies')
  assert.ok(weaknessMatch({ category: 'idor', cwe: null }, { category: null, cwe: 'CWE-639' }), 'category→CWE set')
  assert.equal(weaknessMatch(label, { category: 'xss', cwe: 'CWE-79' }), false, 'different weakness')
})

test('findMatch: a label is found when weakness + file agree and the line is within tolerance', () => {
  const label = { category: 'missing-auth', cwe: 'CWE-306', file: 'repo/app/api/x/route.ts', line: 12 }
  const near = [{ category: 'missing-auth', cwe: null, file: 'app/api/x/route.ts', line: 14, id: 'CG-WEB-001' }]
  assert.ok(findMatch(label, near), 'line 14 is within ±6 of 12')

  const farLine = [{ category: 'missing-auth', cwe: null, file: 'app/api/x/route.ts', line: 99, id: 'CG-WEB-001' }]
  assert.equal(findMatch(label, farLine), null, 'a finding 87 lines away is not the same defect')

  const wrongFile = [{ category: 'missing-auth', cwe: null, file: 'app/api/other.ts', line: 12, id: 'CG-WEB-001' }]
  assert.equal(findMatch(label, wrongFile), null)

  const fileLevel = [{ category: 'missing-auth', cwe: null, file: 'app/api/x/route.ts', line: null, id: 'CG-WEB-001' }]
  assert.ok(findMatch(label, fileLevel), 'a file-level finding matches on file+weakness regardless of line')
})

test('COVERED distinguishes categories with a rule from known gaps', () => {
  assert.ok(COVERED.has('missing-auth'))
  assert.ok(COVERED.has('rls-disabled'))
  assert.equal(COVERED.has('open-cors'), false, 'no CORS rule → a labelled CORS bug is a known gap, not a miss')
  assert.equal(COVERED.has('ssrf'), false)
})

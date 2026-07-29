import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  normalizeSnykSca, normalizeSnykCode, normalizeSnykIac, normalizeSnykContainer,
  normalizeMcpScanResult, normalizeReachability, unwrapMcpContent, snykError,
  hasProvenDataflow, sastKind, readCodeConsent, trustTarget, failureReason,
} from '../plugin/scripts/run_snyk.mjs'
import { grade } from '../plugin/scripts/grader.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const ADAPTER = join(HERE, '..', 'plugin', 'scripts', 'run_snyk.mjs')
const EMPTY_MODEL = { database: { parserVersion: 2, tables: [] } }

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS.
//
// A shape adapter fails SILENTLY. Nothing throws; the output just goes quiet. That is exactly how
// `npm audit`'s no-lockfile error envelope got normalised to `[]` and recorded as "checked, nothing
// found" — a dependency scan that never ran, reported as a clean one. Snyk multiplies the surface:
// four scan types, two transports, and a payload that differs between them.
//
// So these are unit tests over RECORDED Snyk output, and every payload below is annotated with
// where its shape came from and how confident that makes it. Provenance, per scan type:
//
//   snyk_sca_scan       VERIFIED. Shape from Snyk's own recorded fixtures
//                       (snyk/snyk-to-html test/fixtures/no-vulns.json and test-report.json) and
//                       Snyk's parsing struct (snyk/studio-mcp internal/oss/scan_result.go).
//                       Reachability values from test-report-with-reachability.json, whose only two
//                       observed values are "reachable" and "no-path-found", cross-checked against
//                       the legacy REACHABILITY enum in snyk/cli src/lib/snyk-test/legacy.ts
//                       (function | package | not-reachable | no-info).
//   snyk_code_scan      VERIFIED. SARIF 2.1.0; `--json` and `--sarif` are documented as the same
//                       document. Result/rule/codeFlow shapes from snyk/code-client-go
//                       sarif/sarif_types.go and the recorded fixtures test-code-altoroj.json and
//                       snyk/cli test/fixtures/sast/empty-sarif.json (the clean case).
//   snyk_iac_scan       VERIFIED for the issue shape (snyk/snyk-to-html iac-test-report.json —
//                       a top-level ARRAY, one document per file). INFERRED for the clean case:
//                       no recorded zero-issue IaC fixture was found, so `[]` + `ok: true` is
//                       assumed by analogy with SCA. The null branch covers being wrong.
//   snyk_container_scan VERIFIED for the document shape (test-report-container-with-app-vulns.json):
//                       an object like SCA plus `docker` and `platform`. NOT VERIFIED: the
//                       `--app-vulns` variant, which may nest application dependencies differently.
//   MCP transport       VERIFIED from source (snyk/studio-mcp internal/mcp/scan_response_mapper.go,
//                       internal/mcp/snyk_tools.json, internal/mcp/tools.go). The MCP server does
//                       NOT proxy CLI JSON — it replaces SCA and Code output with its own
//                       {success, issueCount, issues[]} summary, and returns HUMAN-READABLE TEXT for
//                       IaC and container. An adapter built on the CLI shape alone would have
//                       returned null on every MCP call, forever, without anything throwing.
//   error envelope      VERIFIED: `{ok: false, error, path}` from snyk/cli
//                       src/lib/formatters/test/format-test-results.ts. Also verified and far more
//                       dangerous: an unauthenticated `snyk test --json` prints a raw Node STACK
//                       TRACE to stdout instead of JSON, and a disabled Snyk Code prints one
//                       English sentence with an empty stderr.
//
// Where a shape is INFERRED it is labelled at the test that uses it.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Recorded payloads
// ---------------------------------------------------------------------------

/** snyk test --json, one advisory. Field set trimmed but structurally faithful. */
const SCA_ONE_VULN = {
  ok: false,
  vulnerabilities: [{
    id: 'SNYK-JS-LODASH-567746',
    title: 'Prototype Pollution',
    severity: 'high',
    moduleName: 'lodash', packageName: 'lodash', name: 'lodash', version: '4.17.15',
    language: 'js', packageManager: 'npm',
    identifiers: { CWE: ['CWE-1321'], CVE: ['CVE-2020-8203'], NSP: 1523, ALTERNATIVE: [] },
    CVSSv3: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H',
    semver: { vulnerable: ['<4.17.19'] },
    from: ['goof@0.0.3', 'lodash@4.17.15'],
    upgradePath: [false, 'lodash@4.17.19'],
    isUpgradable: true, isPatchable: false,
    fixedIn: ['4.17.19'],
  }],
  dependencyCount: 140, org: 'acme', licensesPolicy: null, isPrivate: true,
  packageManager: 'npm', summary: '1 vulnerable dependency path',
  filtered: { ignore: [], patch: [] }, uniqueCount: 1,
}

/** The clean case, verbatim in shape from snyk-to-html's no-vulns.json. */
const SCA_CLEAN = {
  ok: true, vulnerabilities: [], dependencyCount: 140, org: 'acme',
  licensesPolicy: { severities: {} }, isPrivate: true, packageManager: 'maven',
  summary: '0 vulnerable dependency paths', filtered: { ignore: [], patch: [] }, uniqueCount: 11,
}

const withReachability = value => ({
  ...SCA_ONE_VULN,
  vulnerabilities: [{ ...SCA_ONE_VULN.vulnerabilities[0], reachability: value }],
})

/** snyk code test --json === --sarif. One result WITH a proven source→sink path. */
const CODE_SARIF_DATAFLOW = {
  $schema: 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json',
  version: '2.1.0',
  runs: [{
    tool: {
      driver: {
        name: 'SnykCode', semanticVersion: '1.0.0', version: '1.0.0',
        rules: [{
          id: 'javascript/Sqli', name: 'Sqli',
          shortDescription: { text: 'SQL Injection' },
          defaultConfiguration: { level: 'error' },
          help: { markdown: '## Details', text: '' },
          properties: {
            tags: ['javascript', 'Sqli', 'Security', 'SourceHttpParam', 'Taint'],
            categories: ['Security'],
            cwe: ['CWE-89'],
            precision: 'very-high', repoDatasetSize: 42,
            exampleCommitFixes: [], exampleCommitDescriptions: [],
          },
        }],
      },
    },
    results: [{
      ruleId: 'javascript/Sqli', ruleIndex: 0, level: 'error',
      message: { text: 'Unsanitized input from an HTTP parameter flows into query.', markdown: '', arguments: [] },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: 'src/api/orders.ts', uriBaseId: '%SRCROOT%' },
          region: { startLine: 17, endLine: 17, startColumn: 9, endColumn: 44 },
        },
      }],
      fingerprints: { 0: 'b7072247611cfd89' },
      // The dataflow. Note the `location` WRAPPER inside each thread-flow step — verified in
      // code-client-go's ThreadFlowLocation struct, and easy to get wrong.
      codeFlows: [{
        threadFlows: [{
          locations: [
            { location: { id: 0, physicalLocation: { artifactLocation: { uri: 'src/api/orders.ts' }, region: { startLine: 12 } } } },
            { location: { id: 1, physicalLocation: { artifactLocation: { uri: 'src/api/orders.ts' }, region: { startLine: 17 } } } },
          ],
        }],
      }],
      properties: { priorityScore: 802, isAutofixable: false },
    }],
    properties: { coverage: [{ files: 8, isSupported: true, lang: 'TypeScript' }] },
  }],
}

/** The same rule matching with NO codeFlows — a pattern hit, not a traced flow. */
const CODE_SARIF_NO_DATAFLOW = {
  ...CODE_SARIF_DATAFLOW,
  runs: [{
    ...CODE_SARIF_DATAFLOW.runs[0],
    results: [{
      ...CODE_SARIF_DATAFLOW.runs[0].results[0],
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: 'src/api/search.ts' },
          region: { startLine: 30 },
        },
      }],
      codeFlows: [],
    }],
  }],
}

/** A clean Snyk Code run: one run, empty rules and results. NOT an empty `runs` array. */
const CODE_SARIF_CLEAN = {
  $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
  version: '2.1.0',
  runs: [{
    tool: { driver: { name: 'SnykCode', semanticVersion: '1.0.0', version: '1.0.0', rules: [] } },
    results: [],
    properties: { coverage: [{ files: 8, isSupported: true, lang: 'JavaScript' }] },
  }],
}

/** snyk iac test --json — a top-level ARRAY, one document per scanned file. */
const IAC_REPORT = [{
  targetFile: 'k8s/deployment.yaml',
  projectName: 'acme-infra', org: 'acme',
  packageManager: 'k8sconfig', projectType: 'k8sconfig',
  ok: false,
  infrastructureAsCodeIssues: [{
    id: 'SNYK-CC-K8S-1', publicId: 'SNYK-CC-K8S-1',
    title: 'Container is running in privileged mode',
    severity: 'high',
    lineNumber: 12,
    path: ['spec', 'containers[api]', 'securityContext', 'privileged'],
    msg: 'spec.containers[api].securityContext.privileged',
    issue: 'Container is running in privileged mode',
    impact: 'Compromised container could potentially modify the underlying host',
    resolve: 'Set `securityContext.privileged` to `false`',
    iacDescription: {
      issue: 'Container is running in privileged mode',
      impact: 'Compromised container could potentially modify the underlying host',
      resolve: 'Set `securityContext.privileged` to `false`',
    },
    subType: 'Deployment',
    references: ['https://kubernetes.io/docs/concepts/policy/pod-security-policy/'],
    documentation: 'https://security.snyk.io/rules/cloud/SNYK-CC-K8S-1',
    isGeneratedByCustomRule: false, isIgnored: false,
  }],
}]

/** snyk container test --json — an object, with the SCA keys plus `docker` and `platform`. */
const CONTAINER_REPORT = {
  ok: false, dependencyCount: 94, org: 'acme',
  packageManager: 'deb', platform: 'linux/amd64',
  path: 'acme/api:latest', projectName: 'docker-image|acme/api',
  summary: '1 vulnerable dependency path', uniqueCount: 1,
  docker: { baseImage: 'python:3.11-slim-buster', baseImageRemediation: { code: 'OUTDATED_BASE_IMAGE' } },
  vulnerabilities: [{
    id: 'SNYK-DEBIAN10-ZLIB-2976149', title: 'Out-of-bounds Write',
    severity: 'critical', cvssScore: 9.8,
    identifiers: { CVE: ['CVE-2022-37434'], CWE: [], ALTERNATIVE: [] },
    packageName: 'zlib', name: 'zlib/zlib1g', version: '1:1.2.11.dfsg-1+deb10u1',
    packageManager: 'debian:10', language: 'linux',
    from: ['docker-image|acme/api@latest', 'meta-common-packages@meta', 'zlib/zlib1g@1:1.2.11.dfsg-1+deb10u1'],
    upgradePath: [], isUpgradable: false, isPatchable: false,
    nearestFixedInVersion: '1:1.2.11.dfsg-1+deb10u2',
  }],
}

/** The MCP summary. NOT the CLI JSON — this is what `snyk_sca_scan` actually answers with. */
const MCP_SCA = {
  content: [{
    type: 'text',
    text: JSON.stringify({
      success: true, issueCount: 1,
      issues: [{
        id: 'SNYK-JS-LODASH-567746', title: 'Prototype Pollution', severity: 'high',
        cwes: ['CWE-1321'], cves: ['CVE-2020-8203'],
        packageName: 'lodash', version: '4.17.15', ecosystem: 'npm',
        fixedIn: ['4.17.19'], isTransitiveDependency: true, introducedThrough: ['goof@0.0.3'],
      }],
    }),
  }],
}

const MCP_CODE = {
  content: [{
    type: 'text',
    text: JSON.stringify({
      success: true, issueCount: 1,
      issues: [{
        id: 'javascript/Sqli', title: 'SQL Injection', severity: 'high',
        cwes: ['CWE-89'], filePath: 'src/api/orders.ts', line: 17, column: 9,
        message: 'Unsanitized input flows into query.',
        dataflow: [{ filePath: 'src/api/orders.ts', line: 12 }, { filePath: 'src/api/orders.ts', line: 17 }],
        fingerPrint: 'b7072247611cfd89',
      }],
    }),
  }],
}

// ---- Failure payloads, CAPTURED FROM A REAL RUN of snyk 1.1306.2 on this machine -------------
// (installed, no SNYK_TOKEN). These four are transcripts, not reconstructions.

/** `snyk test --json` and `snyk container test --json`, unauthenticated. */
const ERROR_ENVELOPE = {
  ok: false,
  error: 'Use `snyk auth` to authenticate.',
  path: 'E:\\Tester\\repo',
}

/** `snyk iac test --json`, unauthenticated: a bare STACK TRACE on stdout. Not JSON at all. */
const IAC_STACK_TRACE = `FailedToGetIacOrgSettingsError: Failed to fetch IaC organization settings
    at C:\\snapshot\\project\\dist\\cli\\webpack:\\snyk\\src\\cli\\commands\\test\\iac\\local-execution\\org-settings\\get-iac-org-settings.ts:31:23
    at makeRequestWrapper (C:\\snapshot\\project\\dist\\cli\\webpack:\\snyk\\src\\lib\\request\\index.ts:27:7)
    at processTicksAndRejections (node:internal/process/task_queues:103:5)`

/** `snyk_sca_scan` over `snyk mcp -t stdio`, on an untrusted folder. The trust gate fires first. */
const MCP_UNTRUSTED = {
  content: [{
    type: 'text',
    text: "Error: folder 'E:\\Tester\\repo' is not trusted. Please run 'snyk_trust' first",
  }],
}

// ---- Failure payloads sourced from Snyk's source rather than a run (labelled as such) ---------
const MCP_UNAUTHENTICATED = { content: [{ type: 'text', text: "User not authenticated. Please run 'snyk_auth' first" }] }
const AUTH_STACK_TRACE = 'Error: Authentication failed. Please check the API token on https://snyk.io\n    at Object.<anonymous> (/snyk/dist/cli/index.js:1:1)'
const CODE_DISABLED = 'Info: Snyk Code is not enabled for org acme: enable in Settings > Snyk Code'

/** Wrap observations into the adapter's output envelope, the way grade() consumes it. */
function snykScan(scans) {
  const base = {
    sca: { ran: false, observations: null, reason: 'not run in this test' },
    code: { ran: false, observations: null, reason: 'not run in this test' },
    iac: { ran: false, observations: null, reason: 'not run in this test' },
    container: { ran: false, observations: null, reason: 'not run in this test' },
  }
  for (const [k, v] of Object.entries(scans)) {
    base[k] = Array.isArray(v) ? { ran: true, observations: v, reason: null } : v
  }
  return { available: true, authenticated: true, scans: base }
}

// ---------------------------------------------------------------------------
// snyk_sca_scan
// ---------------------------------------------------------------------------

test('snyk_sca_scan: the CLI document is understood', () => {
  const out = normalizeSnykSca(SCA_ONE_VULN)
  assert.equal(out.length, 1)
  assert.equal(out[0].kind, 'dep-vuln')
  assert.equal(out[0].advisorySeverity, 'high')
  assert.equal(out[0].source, 'snyk')
  assert.match(out[0].detail, /Prototype Pollution/)
  assert.match(out[0].subject, /lodash@4\.17\.15/)
})

test('snyk_sca_scan: --all-projects returns an ARRAY, and one project returns a bare object', () => {
  // Snyk strips the array when there is exactly one result, so an adapter that assumed either
  // shape alone would silently drop half the world's monorepos or all of its single projects.
  const many = normalizeSnykSca([SCA_ONE_VULN, SCA_CLEAN])
  assert.equal(many.length, 1)
  assert.equal(normalizeSnykSca(SCA_ONE_VULN).length, 1)
})

test('snyk_sca_scan: reachability values are reduced to three, and no-info is NOT a firm no', () => {
  assert.equal(normalizeReachability('reachable'), 'reachable')
  assert.equal(normalizeReachability('function'), 'reachable', 'the legacy enum spells a proven call path "function"')
  assert.equal(normalizeReachability('no-path-found'), 'not-reachable', 'the value observed in real output')
  assert.equal(normalizeReachability('not-reachable'), 'not-reachable')
  // The deliberate under-claim. `no-info` and `not-reachable` are SEPARATE values in Snyk's own
  // legacy enum, so reading `no-info` as "no path exists" would print a pass we did not earn — and
  // a pass is an instruction to stop looking.
  assert.equal(normalizeReachability('no-info'), 'unknown')
  assert.equal(normalizeReachability('package'), 'unknown', 'package-level reach does not prove the function is called')
  assert.equal(normalizeReachability('not-applicable'), 'unknown')
  assert.equal(normalizeReachability(undefined), 'unknown')
})

// ---------------------------------------------------------------------------
// The confidence win — asserted through grade(), never against a literal
// ---------------------------------------------------------------------------

test('SCA reachable → strong evidence → likely', () => {
  // This is the whole reason Snyk is worth wiring up. run_dep_audit must cap every dependency CVE
  // at needs-review because it cannot tell whether the vulnerable function is ever called.
  const r = grade(EMPTY_MODEL, { scanners: { snyk: snykScan({ sca: normalizeSnykSca(withReachability('reachable')) }) } })
  const f = r.findings.find(x => x.id === 'CG-SNYK-001')
  assert.ok(f, 'a reachable advisory must produce a finding')
  assert.equal(f.evidence.strength, 'strong')
  assert.equal(f.confidence, 'likely')
  assert.match(f.evidence.why, /traced a call path/i)
})

test('SCA not-reachable → NOT a finding, a coverage row saying present-but-unreached', () => {
  // The unreachable-CVE false positive (FP-16), deleted with data instead of a caveat. It must not
  // become a silent drop either: the package still has to appear in the ledger.
  const r = grade(EMPTY_MODEL, { scanners: { snyk: snykScan({ sca: normalizeSnykSca(withReachability('no-path-found')) }) } })
  assert.equal(r.findings.filter(f => f.id === 'CG-SNYK-001').length, 0, 'an unreached CVE is not a finding')
  const row = r.coverage.snyk.pass.find(s => /lodash/.test(s.subject))
  assert.ok(row, 'it must still be accounted for')
  assert.match(row.note, /no path from your code/i)
  assert.match(row.note, /dynamic require or reflection/i, 'a pass must state the limit that could break it')
})

test('SCA unknown reachability → weak → needs-review, exactly as today', () => {
  const r = grade(EMPTY_MODEL, { scanners: { snyk: snykScan({ sca: normalizeSnykSca(withReachability('no-info')) }) } })
  const f = r.findings.find(x => x.id === 'CG-SNYK-001')
  assert.equal(f.evidence.strength, 'weak')
  assert.equal(f.confidence, 'needs-review')
  assert.match(f.assumption, /reached at runtime/i)
})

test('SCA with no reachability field at all is unknown, not assumed safe', () => {
  const r = grade(EMPTY_MODEL, { scanners: { snyk: snykScan({ sca: normalizeSnykSca(SCA_ONE_VULN) }) } })
  const f = r.findings.find(x => x.id === 'CG-SNYK-001')
  assert.equal(f.confidence, 'needs-review')
})

// ---------------------------------------------------------------------------
// snyk_code_scan — SARIF and dataflow
// ---------------------------------------------------------------------------

test('snyk_code_scan: SARIF is understood, and the rule CWE picks the kind', () => {
  const out = normalizeSnykCode(CODE_SARIF_DATAFLOW)
  assert.equal(out.length, 1)
  assert.equal(out[0].kind, 'sast-sqli')
  assert.equal(out[0].cwe, 'CWE-89')
  assert.equal(out[0].at.file, 'src/api/orders.ts')
  assert.equal(out[0].at.line, 17)
  assert.equal(out[0].hasDataflow, true)
  assert.equal(out[0].advisorySeverity, 'high', 'SARIF level error means Snyk-high')
})

test('a proven source→sink path needs at least two steps', () => {
  // One thread-flow location is the sink on its own — Snyk pointing at where the bad thing happens,
  // not at how tainted data got there. Counting that as a dataflow would hand `likely` to a plain
  // pattern match, which is the entire distinction this field exists to draw.
  assert.equal(hasProvenDataflow(CODE_SARIF_DATAFLOW.runs[0].results[0]), true)
  assert.equal(hasProvenDataflow({ codeFlows: [{ threadFlows: [{ locations: [{ location: {} }] }] }] }), false)
  assert.equal(hasProvenDataflow({ codeFlows: [] }), false)
  assert.equal(hasProvenDataflow({}), false)
})

test('Snyk Code dataflow → strong → likely; no dataflow → weak → needs-review', () => {
  const withFlow = grade(EMPTY_MODEL, { scanners: { snyk: snykScan({ code: normalizeSnykCode(CODE_SARIF_DATAFLOW) }) } })
  const a = withFlow.findings.find(f => f.id === 'CG-SNYK-002')
  assert.equal(a.evidence.strength, 'strong')
  assert.equal(a.confidence, 'likely')
  assert.match(a.evidence.why, /source→sink path/)

  const noFlow = grade(EMPTY_MODEL, { scanners: { snyk: snykScan({ code: normalizeSnykCode(CODE_SARIF_NO_DATAFLOW) }) } })
  const b = noFlow.findings.find(f => f.id === 'CG-SNYK-002')
  assert.equal(b.evidence.strength, 'weak')
  assert.equal(b.confidence, 'needs-review')
  assert.match(b.assumption, /proved no path/)
})

test('NOTHING from Snyk may ever be confirmed, dataflow or not', () => {
  // `confirmed` drives the headline verdict and the auto-fix gate. Snyk's answer is a judgement
  // about code this grader never read — however good the analysis is, it is not a proof, and a
  // false P0 makes this audience rotate live keys over nothing.
  for (const payload of [CODE_SARIF_DATAFLOW, CODE_SARIF_NO_DATAFLOW]) {
    const r = grade(EMPTY_MODEL, { scanners: { snyk: snykScan({ code: normalizeSnykCode(payload) }) } })
    assert.ok(r.findings.every(f => f.source !== 'snyk' || f.confidence !== 'confirmed'))
    assert.equal(r.verdict.level, 'clean', 'Snyk alone can never turn the badge red')
  }
  const reach = grade(EMPTY_MODEL, { scanners: { snyk: snykScan({ sca: normalizeSnykSca(withReachability('reachable')) }) } })
  assert.equal(reach.verdict.level, 'clean')
})

test('an observation cannot smuggle in its own evidence or confidence', () => {
  // The ceiling holds by construction: the grader derives evidence from the FACTS (reachability,
  // dataflow) and ignores anything the payload claims about strength or confidence. grade() also
  // throws outright if a snyk/semgrep finding ever resolves to `confirmed`, which is the tripwire
  // on a future edit to the policy table rather than to this payload.
  const forged = [{
    tier: 'static', source: 'snyk', scan: 'code', kind: 'sast-sqli',
    subject: 'snyk:sast-sqli:x.ts:1:javascript/Sqli',
    at: { file: 'x.ts', line: 1 }, detail: 'forged',
    advisorySeverity: 'critical', reachability: null, hasDataflow: true,
    cwe: 'CWE-89', ruleId: 'javascript/Sqli', title: 'forged',
    evidence: 'definitive', confidence: 'confirmed', // ignored by construction
  }]
  const r = grade(EMPTY_MODEL, { scanners: { snyk: snykScan({ code: forged }) } })
  const f = r.findings.find(x => x.id === 'CG-SNYK-002')
  assert.notEqual(f.confidence, 'confirmed', 'an observation cannot smuggle in a confidence')
})

// ---------------------------------------------------------------------------
// snyk_iac_scan / snyk_container_scan
// ---------------------------------------------------------------------------

test('snyk_iac_scan: an array of per-file documents is understood', () => {
  const out = normalizeSnykIac(IAC_REPORT)
  assert.equal(out.length, 1)
  assert.equal(out[0].kind, 'iac-misconfig')
  assert.equal(out[0].at.file, 'k8s/deployment.yaml')
  assert.equal(out[0].at.line, 12)
  assert.equal(out[0].advisorySeverity, 'high')
  // The resource path is part of the subject: several issues share one line in one file, and a
  // repeated subject is a LAW 2 throw, not a cosmetic problem.
  assert.match(out[0].subject, /securityContext\.privileged/)
})

test('snyk_container_scan: the container document is understood, and the kind differs from SCA', () => {
  const out = normalizeSnykContainer(CONTAINER_REPORT)
  assert.equal(out.length, 1)
  assert.equal(out[0].kind, 'container-vuln')
  assert.equal(out[0].advisorySeverity, 'critical')
  const r = grade(EMPTY_MODEL, { scanners: { snyk: snykScan({ container: out }) } })
  const f = r.findings.find(x => x.id === 'CG-SNYK-007')
  // Capped at P1 like every other dependency advisory: one critical CVE must not grade P0 from
  // Snyk and P1 from npm-audit, or the badge depends on which tool the user installed.
  assert.equal(f.severity, 'P1')
  assert.equal(f.confidence, 'needs-review')
})

// ---------------------------------------------------------------------------
// THE CONTRACT: [] means recognised-and-empty, null means not understood
// ---------------------------------------------------------------------------

test('THE CONTRACT: a clean scan is [], every failure is null', () => {
  // Collapsing these two is the defect this whole file exists for. It is what made the npm-audit
  // adapter answer [] to an ENOLOCK error envelope, so the grader recorded the dependency scan as a
  // PASS — "checked, nothing found" over a check that never ran.

  // ...recognised and genuinely empty.
  assert.deepEqual(normalizeSnykSca(SCA_CLEAN), [])
  assert.deepEqual(normalizeSnykCode(CODE_SARIF_CLEAN), [])
  assert.deepEqual(normalizeSnykIac([{ targetFile: 'main.tf', ok: true, infrastructureAsCodeIssues: [] }]), [])

  // ...not recognised. Unauthenticated, in every form Snyk actually produces — and it produces
  // three different ones, only one of which is JSON.
  assert.equal(normalizeSnykSca(ERROR_ENVELOPE), null, 'the real {ok,error,path} envelope')
  assert.equal(normalizeSnykCode(ERROR_ENVELOPE), null, 'snyk code test answers with the same envelope')
  assert.equal(normalizeSnykContainer(ERROR_ENVELOPE), null)
  assert.equal(normalizeSnykIac(IAC_STACK_TRACE), null, 'snyk iac test answers with a bare stack trace')
  assert.equal(normalizeSnykSca(AUTH_STACK_TRACE), null)
  assert.equal(normalizeSnykSca(MCP_UNAUTHENTICATED), null, 'the MCP refusal sentence')
  assert.equal(normalizeSnykCode(CODE_DISABLED), null, 'Snyk Code not enabled for the org')

  // ...untrusted folder, wrapped in the MCP content envelope.
  assert.equal(normalizeSnykSca(MCP_UNTRUSTED), null)
  assert.equal(normalizeSnykIac(MCP_UNTRUSTED), null)
  assert.equal(normalizeSnykCode(MCP_UNTRUSTED), null)

  // ...and shapes nobody recognises.
  assert.equal(normalizeSnykSca({ something: 'else' }), null)
  assert.equal(normalizeSnykCode({ runs: 'not an array' }), null)
  assert.equal(normalizeSnykIac({ infrastructureAsCodeIssues: 'nope' }), null)
  assert.equal(normalizeSnykContainer(null), null)
  assert.equal(normalizeSnykSca([]), null, 'an empty array says nothing about whether a scan happened')
})

test('an error envelope that ALSO carries an empty results array is still a failure', () => {
  // The exact trap that produced the original defect, in Snyk's vocabulary. `ok: false` alone is
  // NOT an error — it is how Snyk says "I found vulnerabilities" — so the error key has to win
  // outright without `ok` being consulted.
  assert.equal(normalizeSnykSca({ ...ERROR_ENVELOPE, vulnerabilities: [] }), null)
  assert.ok(snykError({ ...ERROR_ENVELOPE, vulnerabilities: [] }))
  // ...while a genuine "not ok, here are the vulns" document is not an error at all.
  assert.equal(snykError(SCA_ONE_VULN), null)
  assert.equal(normalizeSnykSca(SCA_ONE_VULN).length, 1)
})

test('a failure is explained in words the user can act on', () => {
  assert.match(failureReason(ERROR_ENVELOPE, snykError(ERROR_ENVELOPE), 'snyk test'), /snyk auth|SNYK_TOKEN/)
  assert.match(failureReason(AUTH_STACK_TRACE, null, 'snyk test'), /snyk auth|SNYK_TOKEN/)
  // The IaC stack trace never says "auth" — it is an auth failure wearing the name of a settings
  // fetch, and without that being recognised the user is told "unrecognised shape" and sent nowhere.
  assert.match(failureReason(IAC_STACK_TRACE, null, 'snyk iac test'), /not authenticated/)
  // Trust must beat auth: the MCP server refuses an untrusted folder before it ever looks at the
  // token, so reporting this as an auth problem would send the user to fix the wrong thing.
  assert.match(failureReason(MCP_UNTRUSTED, null, 'snyk_sca_scan'), /not trusted/)
  assert.match(failureReason(CODE_DISABLED, null, 'snyk code test'), /not enabled for this Snyk organisation/)
  assert.match(failureReason('{}', null, 'snyk test'), /shape this adapter does not recognise/)
})

// ---------------------------------------------------------------------------
// The MCP transport — a different payload behind the same tool name
// ---------------------------------------------------------------------------

test('the MCP envelope is unwrapped, and the summary shape is understood', () => {
  // `snyk mcp` does not proxy CLI JSON: it throws the CLI output away and returns its own summary,
  // JSON-encoded inside a text content block. An adapter expecting `snyk test --json` back from
  // `snyk_sca_scan` would answer null on every real call — a permanent coverage gap with nothing
  // throwing to explain it.
  assert.deepEqual(unwrapMcpContent({ content: [{ type: 'text', text: '{"a":1}' }] }), { a: 1 })
  const out = normalizeSnykSca(MCP_SCA)
  assert.equal(out.length, 1)
  assert.equal(out[0].kind, 'dep-vuln')
  assert.equal(out[0].reachability, 'unknown', 'the MCP summary carries no reachability field at all')
})

test('MCP Snyk Code carries its dataflow directly, and it still reaches only likely', () => {
  const out = normalizeSnykCode(MCP_CODE)
  assert.equal(out.length, 1)
  assert.equal(out[0].kind, 'sast-sqli')
  assert.equal(out[0].hasDataflow, true)
  const r = grade(EMPTY_MODEL, { scanners: { snyk: snykScan({ code: out }) } })
  const f = r.findings.find(x => x.id === 'CG-SNYK-002')
  assert.equal(f.confidence, 'likely')
})

test('MCP: success:false with no issues is a failed scan, not a clean one', () => {
  // `success` is ambiguous — it could mean "the command ran" or, like the CLI's `ok`, "nothing was
  // found". Both readings are honoured rather than guessed: no issues means null (never a false
  // clean), issues present means report them (never a discarded finding).
  assert.equal(normalizeMcpScanResult({ success: false, issueCount: 0, issues: [] }), null)
  assert.equal(normalizeMcpScanResult({ success: true, issueCount: 0, issues: [] }).length, 0)
  assert.equal(normalizeMcpScanResult({ success: false, issueCount: 1, issues: [{ id: 'X', title: 'X', severity: 'high', packageName: 'p', version: '1' }] }).length, 1)
})

test('an issue the user already ignored in Snyk is not re-raised', () => {
  const out = normalizeMcpScanResult({
    success: true, issueCount: 1,
    issues: [{ id: 'X', title: 'X', severity: 'high', packageName: 'p', version: '1', isIgnored: true }],
  })
  assert.deepEqual(out, [], 'recognised, and deliberately empty — not null')
})

// ---------------------------------------------------------------------------
// Kind classification
// ---------------------------------------------------------------------------

test('SAST kinds come from CWE first and the rule id second', () => {
  assert.equal(sastKind(['CWE-89'], 'javascript/Sqli'), 'sast-sqli')
  assert.equal(sastKind(['CWE-79'], 'javascript/Xss'), 'sast-xss')
  assert.equal(sastKind(['CWE-918'], 'javascript/Ssrf'), 'sast-ssrf')
  assert.equal(sastKind(['CWE-23'], 'javascript/PT'), 'sast-path-traversal')
  assert.equal(sastKind([], 'javascript/Sqli'), 'sast-sqli', 'the rule id carries it when the CWE is missing')
  // Grade or declare: a rule we cannot classify is still graded, never dropped.
  assert.equal(sastKind(['CWE-327'], 'javascript/WeakHash'), 'sast-other')
  // A three-segment rule id is real (javascript/HardcodedSecret/test) and must not break parsing.
  assert.equal(sastKind([], 'javascript/HardcodedSecret/test'), 'sast-other')
})

test('a result kind no rule owns is DECLARED, never silently dropped', () => {
  const r = grade(EMPTY_MODEL, {
    scanners: {
      snyk: snykScan({
        sca: [{
          tier: 'static', source: 'snyk', scan: 'sca', kind: 'sbom-license',
          subject: 'snyk:sbom-license:pkg', at: { file: null, line: null }, detail: 'a kind from a future Snyk tool',
          advisorySeverity: 'medium', reachability: null, hasDataflow: null, cwe: null, ruleId: 'x', title: 'x',
        }],
      }),
    },
  })
  const row = r.coverage.snyk.undeterminable.find(s => s.subject === 'snyk:sbom-license:pkg')
  assert.ok(row, 'an unowned kind must reach the ledger')
  assert.match(row.note, /no rule owns/)
})

// ---------------------------------------------------------------------------
// LAW 2
// ---------------------------------------------------------------------------

test('one package with two advisories does not crash LAW 2', () => {
  // Snyk lists one row per (issue, dependency path), so one package with several CVEs — and one CVE
  // reached by several paths — are both normal input. A repeated subject is answered with a throw,
  // which would crash the whole report instead of printing it.
  const twoAdvisories = {
    ...SCA_ONE_VULN,
    vulnerabilities: [
      SCA_ONE_VULN.vulnerabilities[0],
      { ...SCA_ONE_VULN.vulnerabilities[0], id: 'SNYK-JS-LODASH-590103', title: 'Command Injection' },
      // The same advisory again, via a second dependency path — verbatim duplicate.
      { ...SCA_ONE_VULN.vulnerabilities[0], from: ['goof@0.0.3', 'tap@5.8.0', 'lodash@4.17.15'] },
    ],
  }
  const out = normalizeSnykSca(twoAdvisories)
  assert.equal(out.length, 2, 'two distinct advisories, and the repeated path collapsed')

  const r = grade(EMPTY_MODEL, { scanners: { snyk: snykScan({ sca: out }) } })
  const c = r.coverage.snyk.counts
  assert.equal(c.pass + c.fail + c.undeterminable + c.allowlisted, r.coverage.snyk.enumerated)
  assert.equal(r.findings.filter(f => f.id === 'CG-SNYK-001').length, 2)
})

test('every Snyk subject enters the ledger, and every set still adds up', () => {
  const r = grade(EMPTY_MODEL, {
    scanners: {
      snyk: snykScan({
        sca: normalizeSnykSca(withReachability('reachable')),
        code: normalizeSnykCode(CODE_SARIF_DATAFLOW),
        iac: normalizeSnykIac(IAC_REPORT),
        container: normalizeSnykContainer(CONTAINER_REPORT),
      }),
    },
  })
  for (const [name, set] of Object.entries(r.coverage)) {
    const c = set.counts
    assert.equal(c.pass + c.fail + c.undeterminable + c.allowlisted, set.enumerated, `LAW 2 broken in "${name}"`)
  }
  assert.equal(r.coverage.snyk.counts.fail, 4)
})

test('a Snyk subject can be allowlisted', () => {
  const observations = normalizeSnykSca(SCA_ONE_VULN)
  const subject = observations[0].subject
  const r = grade(EMPTY_MODEL, { scanners: { snyk: snykScan({ sca: observations }) }, allowlist: [subject] })
  assert.ok(!r.findings.some(f => f.id === 'CG-SNYK-001'))
  assert.equal(r.coverage.snyk.counts.allowlisted, 1)
})

// ---------------------------------------------------------------------------
// The consent gate
// ---------------------------------------------------------------------------

test('Snyk Code consent is OFF unless the user said yes, in one of exactly two places', () => {
  assert.equal(readCodeConsent({}).granted, false)
  assert.equal(readCodeConsent({ flag: true }).source, 'flag')
  assert.equal(readCodeConsent({ scope: { snyk: { code_scan_uploads_source: true } } }).source, 'scope-file')
  // Anything short of an explicit `true` is a no. A missing key, a typo'd value and an empty scope
  // file must all mean "do not upload this person's source".
  assert.equal(readCodeConsent({ scope: { snyk: { code_scan_uploads_source: 'yes' } } }).granted, false)
  assert.equal(readCodeConsent({ scope: {} }).granted, false)
  assert.equal(readCodeConsent({ scope: null }).granted, false)
})

test('Code skipped for consent is a NAMED coverage row, never a silent gap', () => {
  const r = grade(EMPTY_MODEL, {
    scanners: {
      snyk: snykScan({
        sca: normalizeSnykSca(SCA_CLEAN),
        code: {
          ran: false, observations: null,
          reason: "Snyk Code (SAST) uploads your source to Snyk's cloud, and consent was not given, so no dataflow analysis ran (pass --code, or set snyk.code_scan_uploads_source: true in claudeguard.scope.yml)",
        },
      }),
    },
  })
  const row = r.coverage.scanCoverage.undeterminable.find(s => s.subject === 'scan:snyk-code')
  assert.ok(row, 'a skipped scan must be visible')
  assert.match(row.note, /uploads your source/i)
  assert.match(row.note, /consent/i)
  // ...and the scan that DID run is a pass, so the two are told apart.
  const ok = r.coverage.scanCoverage.pass.find(s => s.subject === 'scan:snyk-sca')
  assert.ok(ok)
  assert.match(ok.note, /returned 0 result/)
})

test('trust is granted to the repo under scan and never to a parent', () => {
  // A trust grant covers every subdirectory, so trusting a home directory silently authorises every
  // future scan of every sibling project on the machine.
  assert.equal(trustTarget('/home/dev/app', '/home/dev').refused, null)
  assert.ok(trustTarget('/home/dev', '/home/dev').refused, 'the home directory itself is too wide')
  assert.ok(trustTarget('/', '/home/dev').refused, 'a filesystem root is not a project')
})

// ---------------------------------------------------------------------------
// Dedup — three tools, one defect
// ---------------------------------------------------------------------------

const COMPOSE_MODEL = {
  database: { parserVersion: 2, tables: [] },
  iac: {
    compose: [{
      file: 'docker-compose.yml',
      dockerSocket: null, privileged: { line: 12 }, hostNetwork: null,
      exposedDbPorts: [], bakedSecrets: [],
    }],
  },
}

test('snyk + semgrep + a native rule on one file:line collapse into ONE finding', () => {
  // Volume is what destroys trust, not any single finding. Printed straight through, one
  // `privileged: true` arrives three times with three severities and the reader cannot tell that
  // from three separate problems.
  const r = grade(COMPOSE_MODEL, {
    scanners: {
      sast: {
        engine: 'semgrep', available: true, count: 1,
        findings: [{ file: 'docker-compose.yml', line: 12, rule: 'yaml.docker-compose.security.privileged-service', engineSeverity: 'ERROR', message: 'privileged service' }],
      },
      snyk: snykScan({
        iac: [{
          tier: 'static', source: 'snyk', scan: 'iac', kind: 'iac-misconfig',
          subject: 'snyk:iac-misconfig:docker-compose.yml:12:SNYK-CC-K8S-1',
          at: { file: 'docker-compose.yml', line: 12 },
          detail: 'Container is running in privileged mode',
          advisorySeverity: 'high', reachability: null, hasDataflow: null,
          cwe: null, ruleId: 'SNYK-CC-K8S-1', title: 'Container is running in privileged mode',
        }],
      }),
    },
  })

  const here = r.findings.filter(f => f.evidence.at[0]?.file === 'docker-compose.yml' && f.evidence.at[0]?.line === 12)
  assert.equal(here.length, 1, 'three tools, one defect, one finding')

  const survivor = here[0]
  // The native rule wins: this grader is the single severity authority, and its own rules read the
  // file directly. An external tool's opinion about the same line does not overwrite that.
  assert.equal(survivor.id, 'CG-IAC-006')
  assert.equal(survivor.source, null)
  assert.equal(survivor.severity, 'P1')
  assert.equal(survivor.confidence, 'confirmed')

  // Nothing is lost: the other two are recorded on it, each carrying its own severity.
  assert.equal(survivor.corroboration.length, 2)
  assert.deepEqual(survivor.corroboration.map(c => c.source).sort(), ['semgrep', 'snyk'])
  assert.ok(survivor.corroboration.every(c => c.severity && c.confidence && c.why))

  // ...and their coverage rows point at where their findings went, so the "every fail row has a
  // finding" cross-check still holds.
  const sastRow = r.coverage.sast.fail.find(s => s.subject.startsWith('sast:docker-compose.yml:12'))
  assert.match(sastRow.note, /reconciled into CG-IAC-006/)
  const snykRow = r.coverage.snyk.fail.find(s => s.subject.startsWith('snyk:iac-misconfig:docker-compose.yml:12'))
  assert.match(snykRow.note, /reconciled into CG-IAC-006/)
})

test('two findings from the SAME tool at one line are never merged', () => {
  // A compose file really can mount the Docker socket AND run privileged. Reconciliation is about
  // the same fact seen twice by different tools, not about tidying up one tool's enumeration.
  const r = grade({
    database: { parserVersion: 2, tables: [] },
    iac: {
      compose: [{
        file: 'docker-compose.yml',
        dockerSocket: { line: 12 }, privileged: { line: 12 }, hostNetwork: null,
        exposedDbPorts: [], bakedSecrets: [],
      }],
    },
  }, {})
  const ids = r.findings.map(f => f.id).sort()
  assert.deepEqual(ids, ['CG-IAC-005', 'CG-IAC-006'], 'both survive')
})

test('findings whose weakness class cannot be named are never merged', () => {
  // Two genuinely different defects can share a line. Collapsing those would hide one, and a hidden
  // finding is worse than a visible duplicate — so an unclassifiable pair stays as two.
  const r = grade(EMPTY_MODEL, {
    scanners: {
      sast: {
        engine: 'semgrep', available: true, count: 2,
        findings: [
          { file: 'a.ts', line: 5, rule: 'javascript.lang.correctness.useless-eqeq', engineSeverity: 'ERROR' },
        ],
      },
      snyk: snykScan({
        code: [{
          tier: 'static', source: 'snyk', scan: 'code', kind: 'sast-other',
          subject: 'snyk:sast-other:a.ts:5:javascript/WeakHash',
          at: { file: 'a.ts', line: 5 }, detail: 'Weak hashing algorithm',
          advisorySeverity: 'medium', reachability: null, hasDataflow: false,
          cwe: 'CWE-327', ruleId: 'javascript/WeakHash', title: 'Use of a Broken Hash',
        }],
      }),
    },
  })
  const here = r.findings.filter(f => f.evidence.at[0]?.file === 'a.ts' && f.evidence.at[0]?.line === 5)
  assert.equal(here.length, 2, 'unrelated findings at one line stay separate')
})

test('reconciliation is deterministic across two runs of the same input', () => {
  // The bench asserts grade() is byte-identical twice over; the Map iteration inside reconciliation
  // is exactly the kind of thing that can quietly reorder.
  const opts = {
    scanners: {
      sast: { engine: 'semgrep', available: true, count: 1, findings: [{ file: 'docker-compose.yml', line: 12, rule: 'privileged-service', engineSeverity: 'ERROR' }] },
      snyk: snykScan({
        iac: [{
          tier: 'static', source: 'snyk', scan: 'iac', kind: 'iac-misconfig',
          subject: 'snyk:iac-misconfig:docker-compose.yml:12:SNYK-CC-K8S-1',
          at: { file: 'docker-compose.yml', line: 12 }, detail: 'privileged mode',
          advisorySeverity: 'high', reachability: null, hasDataflow: null,
          cwe: null, ruleId: 'SNYK-CC-K8S-1', title: 'Container is running in privileged mode',
        }],
      }),
    },
  }
  assert.deepEqual(grade(COMPOSE_MODEL, opts), grade(COMPOSE_MODEL, opts))
})

// ---------------------------------------------------------------------------
// Severity re-mapping
// ---------------------------------------------------------------------------

test("Snyk's severity is re-mapped, and capped by weakness class rather than trusted verbatim", () => {
  const critDep = grade(EMPTY_MODEL, {
    scanners: { snyk: snykScan({ sca: normalizeSnykSca({ ...SCA_ONE_VULN, vulnerabilities: [{ ...SCA_ONE_VULN.vulnerabilities[0], severity: 'critical' }] }) }) },
  })
  assert.equal(critDep.findings.find(f => f.id === 'CG-SNYK-001').severity, 'P1',
    'a critical upstream advisory is P1 here, exactly as it is for npm-audit')

  const critIac = grade(EMPTY_MODEL, {
    scanners: {
      snyk: snykScan({
        iac: normalizeSnykIac([{
          targetFile: 'main.tf', ok: false,
          infrastructureAsCodeIssues: [{ publicId: 'SNYK-CC-TF-1', title: 'S3 bucket is publicly readable', severity: 'critical', lineNumber: 3, path: ['resource'] }],
        }]),
      }),
    },
  })
  // IaC is uncapped on purpose: a public bucket really is total exposure, and severity is
  // impact-if-true. The uncertainty is paid in confidence, which stays needs-review.
  const f = critIac.findings.find(x => x.id === 'CG-SNYK-006')
  assert.equal(f.severity, 'P0')
  assert.equal(f.confidence, 'needs-review')
  assert.equal(critIac.verdict.level, 'clean', 'an unproven P0 is printed but never reddens the badge')
})

// ---------------------------------------------------------------------------
// The environment CI actually has: no Snyk token, and possibly no Snyk at all
//
// This is the case that has to be right, because it is the one almost every user is in. The
// assertions deliberately do not pin WHICH obstacle stopped the scan — a machine with the CLI
// installed and no token, and one with neither, are both legitimate — only that the adapter names
// one, and never answers with a clean result it did not earn. The environment is a fixture here,
// not a variable to be controlled.
// ---------------------------------------------------------------------------

const runAdapter = () => JSON.parse(execFileSync(process.execPath, [ADAPTER, HERE], {
  encoding: 'utf8', env: { ...process.env, SNYK_TOKEN: '' },
}))

/** Every obstacle the adapter is allowed to report when it could not scan. */
const NAMED_OBSTACLE = /not installed|SNYK_TOKEN|not trusted|not authenticated|consent/

test('without a Snyk token the adapter names WHY, and fabricates no clean result', () => {
  const out = runAdapter()
  assert.deepEqual(out.observations, [], 'no observations, because nothing was observed')
  for (const [name, s] of Object.entries(out.scans)) {
    assert.equal(s.ran, false, `${name} must not claim to have run`)
    assert.equal(s.observations, null, `${name} must be null, not [] — nothing was checked`)
    assert.match(s.reason, NAMED_OBSTACLE, `${name} must say why`)
  }
  assert.equal(out.codeConsent.granted, false, 'source upload is off by default, always')
  assert.match(out.scans.code.reason, /consent/, 'the consent gate is stated whatever else went wrong')
  // Trust is computed even when nothing ran, so the caller knows the ONE folder it may grant —
  // the directory under scan, never a parent.
  assert.equal(out.trustPath, HERE)
})

test('...and the grader turns that into four undeterminable rows, not four passes', () => {
  const r = grade(EMPTY_MODEL, { scanners: { snyk: runAdapter() } })
  for (const scan of ['sca', 'code', 'iac', 'container']) {
    const row = r.coverage.scanCoverage.undeterminable.find(s => s.subject === `scan:snyk-${scan}`)
    assert.ok(row, `scan:snyk-${scan} must be a visible coverage hole`)
    assert.match(row.note, NAMED_OBSTACLE, 'an undeterminable row without a reason is an apology')
  }
  assert.equal(r.coverage.scanCoverage.counts.pass, 0, 'a tool that could not run is never a pass')
  assert.equal(r.coverage.snyk.enumerated, 0, 'declared even when empty — 0 is a real statement')
  assert.equal(r.verdict.level, 'clean')
})

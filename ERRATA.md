# Errata

A numbered ledger of claims this project made and later found to be wrong.

Every entry names the old claim in the words it was actually written in, states what is true, and
says where the correction landed. **Nothing here is deleted or quietly reworded.** A security tool
that edits its own history is asking for a trust it has not earned — and the failure this project
exists to catch, *a confident statement nobody had checked*, is what produced most of the entries
below. Correcting in the open is the only version of the argument that costs us anything.

The retraction text lives **here and only here**. [`SECURITY.md`](SECURITY.md),
[`README.md`](README.md), [`README.he.md`](README.he.md), [`ROADMAP.md`](ROADMAP.md) and
[`.github/dependabot.yml`](.github/dependabot.yml) point at an `ERR-` id instead of repeating the
prose, so there is one copy to keep true.

Ids are append-only, numbered in the order the corrections landed, and never renumbered or reused.

## עברית (בקצרה)

זהו יומן התיקונים של הפרויקט. כל טענה שנטענה כאן ונמצאה שגויה מקבלת מספר (`ERR-001` והלאה), ציטוט
של הטענה המקורית, מה נכון באמת, ואיפה התיקון נכנס. שום דבר לא נמחק ולא נכתב מחדש בשקט: כלי אבטחה
שמוחק את הטעויות של עצמו מבקש אמון שלא הרוויח. הטקסט של כל תיקון נמצא כאן בלבד, ושאר הקבצים מפנים
למספר ה-`ERR` במקום לחזור עליו.

---

## ERR-001 — the live/DAST gate checked one host and opened another

**Claimed.** The Tier-1 / Tier-2 authorization gate documented in
[`core/authorization/legal-gate.md`](core/authorization/legal-gate.md) promised that a probe reaches
only a host listed in `targets`, never a `never_touch` host, and never a default-blocked third-party
provider.

**What is true.** The shipped matcher in `plugin/scripts/_scope.mjs` stripped the scheme with a
regex and cut the authority at the first `/`, so the string the gate validated was not the string
the runner fetched — both were derived separately from the same raw input. Six spellings defeated
it:

- **Userinfo.** `https://staging.myapp.com:443@evil.com` was gated as `staging.myapp.com`, because
  dropping the port from both sides left exactly the allowlisted name — and then fetched from
  `evil.com`. With `localhost:3000`, the target that ships in `SCOPE.example.yml`,
  `https://localhost:3000@169.254.169.254` cleared **both** tiers and reached the cloud-metadata
  service. Out of the box, with the shipped config.
- **`?` and `#` end an authority** for a URL parser and neither is a `/`, so
  `evil.com?x=.staging.example.com` matched `*.staging.example.com`.
- **Trailing root dot.** `api.stripe.com.` is the same name to DNS and a different string to `===`,
  so the third-party blocklist missed it.
- **IPv6 collapse.** `split(':')[0]` is `[` for every `::`-leading literal, so a `[::1]` target
  matched `[::ffff:169.254.169.254]`.
- **Port ignored.** `localhost:3000` licensed `localhost:5432`. An allowlist entry for a web app is
  not a licence to probe the database on the same box.
- **CIDR silently truncated.** `10.0.5.0/24` — the dynamic-testing spec's own example — read the
  `/` as a path and meant the single host `10.0.5.0`.

**Corrected.** Commit `9436f43` (PR #13), shipped in **0.2.0**. Both the gated host and the sent URL
now come from one WHATWG URL parse: `normalizeHost()` returns the host `fetch` will actually open
and `canonicalUrl()` returns the URL the runner may request. Every host-matching case in the
adversarial suite is a regression test for one of the six. Standing narration of five of them lives
in [`core/authorization/legal-gate.md`](core/authorization/legal-gate.md) (the CIDR truncation is
recorded in the commit and in the dynamic-testing gate's own tests).

---

## ERR-002 — the fixture dependencies were called current, and bumping them a loss of test coverage

**Claimed.** Three files a reader consults to decide whether a Dependabot alert matters disagreed
with each other, and two of them were wrong.

- `README.md` said `sample-vulnerable-app/`'s *"dependencies are kept current, so it shouldn't trip
  Dependabot"*, and `sample-vulnerable-app/package.json` said the same.
- `SECURITY.md` and `.github/dependabot.yml` said the opposite — deliberately not current — and then
  gave a false reason for it: upgrading them *"would delete test coverage rather than add safety"*.
- `.github/dependabot.yml` also said automated PRs were *"disabled for both trees"* while
  configuring one.

**What is true.** The fixture dependencies are **not** current, they **do** trip Dependabot, and
that is where this repository's alert count comes from. Bumping one costs nothing: no
`expected.json` in `bench/corpus` expects `CG-DEP-001`, and the dependency-scanning arm is exercised
in `test/dep_audit_shapes.test.mjs` and `test/scanners.test.mjs` against **recorded tool output**,
never against a fixture's installed versions. Several such bumps have been merged with the
benchmark's regression gate green throughout. A fixture dependency bump is **noise, not a risk**.

Separately: `open-pull-requests-limit: 0` stops scheduled **version** updates and cannot stop
**security** updates, which is what the `npm_and_yarn` group PRs are. Those are governed by a
repository setting and cannot be scoped by path from `dependabot.yml` at all — so adding
`bench/corpus` to that file would restate the same false promise in a new place.

**Corrected.** Commit `419b14a` (PR #18), shipped in **0.2.0**. Standing text: the *"Why the
Security tab shows a large alert count"* section of [`SECURITY.md`](SECURITY.md) and the comment
block atop [`.github/dependabot.yml`](.github/dependabot.yml).

---

## ERR-003 — the Supabase spot-check handed the user's anon key to any host they named

**Claimed.** Tier 1 documented — and `plugin/scripts/live_probe.mjs` implemented, for its main
`--url` — that every host contacted has passed the authorization gate first.

**What is true.** The optional Supabase RLS spot-check computed
`normalizeHost(args['supabase-url'])` into a variable it then never used, and built the request from
the **raw argument**, carrying the user's anon key in both an `apikey` and an
`Authorization: Bearer` header. Naming any host on the command line therefore sent that credential
there while the gate had approved a completely different one. The comment beside the unused variable
asked exactly the right question, left it unanswered, and shipped.

Reproduced against the shipped code: with a scope authorising only `app.example.com`, `gateTier1`
returned `allowed:false` for the probe host, and a listener on that unauthorised host still received
the key. This is the same checked-versus-used gap as **ERR-001**, on a second parameter nobody had
looked at, and worse — that one contacted the wrong machine, this one handed it a secret. Found by
an external review.

**Corrected.** Commit `6f22082` (PR #19), shipped in **0.2.0**. The user's own project now gets its
own attestation, `passive_live.supabase_project`, naming that one project and nothing else, and the
request is built from the **canonical form of the attested value** rather than from the argument —
so the host that was checked and the host that is contacted are the same string by construction
rather than by inspection. `never_touch` still wins over it. Twelve tests, including the reproduced
bypass and a control asserting the attested project *is* allowed in every URL form, because a gate
suite that passes by refusing everything is worthless.

---

## ERR-004 — Tier 2 was described as "real attack traffic (injection, IDOR, fuzzing)"

**Claimed.** The tier table in `README.md` described Tier 2 as sending *"real attack traffic
(injection, IDOR, fuzzing)"*, and the `/cg-dast` skill description matched it.

**What is true.** Tier 2 sends **four GET probes**: reflected markup in `q`, a single quote in `id`,
an open-redirect check via `next`, and a CSP header check. There is no IDOR probe. There is no
fuzzing. No crawling, no authenticated flows, no parameter discovery. It is a **smoke test, not a
scanner** — Burp, ZAP or Nuclei are the tools for real DAST.

An external review rated the DAST 2.5/10 and was being generous. The defect being retracted here is
not that the feature is thin; a thin feature honestly described is fine. It is that the README said
something untrue about what the tool does.

**Corrected.** Commit `f7b1d0f`, released as **0.2.0** (PR #20). Standing text: the Tier-2 row and
the note under it in [`README.md`](README.md) and [`README.he.md`](README.he.md), and the `/cg-dast`
skill description. [`ROADMAP.md`](ROADMAP.md) §6 states the choice that remains: build real dynamic
testing behind the existing gate, or keep the smoke test and say so in the name.

---

## ERR-005 — the DAST retraction was announced as complete while half of it was still unmade

**Claimed.** The 0.2.0 release notes said the English and Hebrew READMEs now agreed about what
Tier 2 does — that **ERR-004** was fixed in both halves.

**What is true.** They did not agree. `README.he.md` still carried the overclaim verbatim, in the
language the intended audience actually reads, and so did the English comment above the
`active_dast` block in [`core/authorization/SCOPE.example.yml`](core/authorization/SCOPE.example.yml)
— the template every Tier-2 user copies into their own project. An external review caught it.

Fixing a retraction incompletely is the same class of defect as the claim it retracts, which is why
it gets its own id here rather than being folded into ERR-004.

**Corrected.** Commit `0349a7f`, on the 0.2.0 release branch (PR #20). The Hebrew tier row now
matches the English one — smoke test, not a scanner; no IDOR, no fuzzing — and the scope template
says what the four probes actually are.

---

## ERR-006 — "recall 100% / precision 100% / 0 false positives" was presented as a headline result

**Claimed.** `ROADMAP.md`'s status table opened with *"benchmark at recall 100% / precision 100% /
0 false positives over 8 clean variants, deterministic. This is the part to rely on"*, and its
changelog line read *"Benchmark held at 100% / 100% / 0 throughout"*. Read cold — and quoted onward,
which is what happens to a number in a table — those are detection-rate claims.

**What is true.** They measure a **golden-file regression gate**, and recall is 100% *by
construction*. [`bench/run.mjs`](bench/run.mjs) says so in its own header: `expected.json` for each
case **records what the grader actually produces today**, asserted so it stays that way — the
harness even ships a `--dump` mode for authoring `expected.json` from that output. A vulnerability
the grader misses therefore never becomes a label, so recall cannot fall below 100% except by
regression. Which is exactly what the gate is for, and is a real and useful thing to have.

Stated as what it is: **0 regressions across 18 pinned detections in 7 vulnerable scenarios, and 0
unexpected confirmed findings across 8 clean variants — a corpus authored by this project.** That is
excellent regression protection and a genuine cry-wolf gate. **The real-world detection rate is not
yet measured.** A headline number that cannot go down is a tautology, not a result, and a security
tool that leads with one invites being read as claiming a detection rate it has never measured —
which is the misreading this retraction removes.

The numbers themselves are real, reproducible and unchanged. Only the framing that made them read as
a detection rate is retracted. Where they appear scoped to what they can support — *"the benchmark's
regression gate stayed green, so this change broke nothing"* — they stay.

**Corrected.** This entry, and the reframing that lands with it in [`README.md`](README.md),
[`README.he.md`](README.he.md) and [`ROADMAP.md`](ROADMAP.md). [`ROADMAP.md`](ROADMAP.md) §5 tracks
the only thing that changes the underlying fact: a corpus we did not write.

---

## ERR-007 — "every Dependabot alert points at one of those two fixture trees", while a third tree produced most of them

**Claimed.** [`SECURITY.md`](SECURITY.md) named exactly two directories of intentionally insecure
code — `sample-vulnerable-app/` and `bench/corpus/**` — and then stated: *"Every Dependabot alert on
this repository points at one of those two fixture trees."* [`README.md`](README.md) made the
narrower version of the same claim under *"Why is there a 'vulnerable app' in this repo?"*, naming
only `sample-vulnerable-app/`: *"Its **dependencies are not kept current**, so it does trip
Dependabot — every alert on this repository points at a fixture."*
[`.github/dependabot.yml`](.github/dependabot.yml) listed the same two trees and told the reader what
to expect: *"GitHub's Security tab shows a large Dependabot ALERT count for this repo. Those alerts
are the fixtures."*

**What is true.** There was a **third** fixture tree, unnamed in all three places, and it was the
dominant source of the alerts: `bench/wild/*/repo/`, the real third-party source vendored for the
wild benchmark in 0.3.0. Those nine manifests declared **429 dependency entries** between them —
`bench/wild/chartgpt-service-role-client` alone had 96, `owasp-nodegoat` a deliberately ancient 2016
Grunt/Mongo/Cypress toolchain — against **5** in `sample-vulnerable-app` and 1–6 per `bench/corpus`
case. The repository's alert count stood at about **122**.

So the conclusion each document reached was right — no alert was ever reachable from anything this
tool ships, and this project still has zero runtime dependencies — but it was reached over an
inventory that was missing the part that mattered. "A large count, and here are the two trees it
comes from" is a false account of a number when a third tree produced most of it. Naming the trees
is the whole content of the reassurance; getting that list wrong is not a detail.

The second half of the claim was also a choice presented as a fact of nature. **Most of those 429
entries could simply be deleted.** [`plugin/scripts/project_model.mjs`](plugin/scripts/project_model.mjs)
reads a manifest in exactly two places — framework detection (`const deps = …`) and
`SERVER_FRAMEWORKS[*].pkgs` — and both consult a closed, hard-coded set of names; every other pass
keys off imports in the source. A dependency outside that set is invisible to the engine, so it buys
the corpus no detection and costs it an alert. 0.3.1 keeps the observable ones at their real upstream
pins and drops the other **429**, which cut the alert count by roughly an order of magnitude. The
wild scorecard is **byte-identical** across the change (10/16 detected, 9/16 confirmed, 0 candidate
false positives), the regression gate stayed green, and
[`test/wild_manifest_hygiene.test.mjs`](test/wild_manifest_hygiene.test.mjs) now fails if a new case
re-imports a full manifest, or if the engine renames something the allowlist still permits.

Two honest residues, stated rather than rounded to zero:

- **This is a fidelity trade.** The vendored `package.json` files are now a subset of upstream at the
  pinned SHA. They always were a subset of the upstream *tree* — no wild case was ever a full clone
  — but a trimmed file is a modified file, and a reader diffing against `source_url` will find it.
  The rule is mechanical and recorded in
  [`bench/wild/observable-packages.mjs`](bench/wild/observable-packages.mjs): nothing is bumped, and
  nothing the engine can read is removed.
- **The count is not zero and should not be.** `next 14.2.3`, `express ^4.13.4`, `electron ^36`,
  `vite ^6.2.2` and friends are exactly what the engine reads, so they stay at the real pins and
  keep raising alerts. A fixture-only residue is the correct end state, not a bug to drive to zero.

**Corrected.** This entry, and the changes that land with it in 0.3.1: the trim and its guard test,
and the inventory corrected in [`SECURITY.md`](SECURITY.md), [`README.md`](README.md),
[`README.he.md`](README.he.md) and [`.github/dependabot.yml`](.github/dependabot.yml). Alert
*visibility* remains a repository setting, which no file in this repo can change.

---

## ERR-008 — the delegated half of the engine scored zero by construction, and the benchmark called it "no rule"

**Claimed.** [`bench/wild.mjs`](bench/wild.mjs) printed, for every labelled `rce`, `ssrf`,
`injection-sql` and `xss` finding it did not match: *"○ GAP [category] file:line — no rule for this
category (known)"*, and its header explained the convention: *"Categories ClaudeGuardIL has no rule
for (open-cors, ssrf, …) are reported separately as known COVERAGE GAPS, so 'missed because no rule'
is not blamed on detection quality."* The scorecard totalled them as *"labels in categories with NO
rule (coverage gaps): 12"*, and [`README.md`](README.md) carried the same 12 onward.

**What is true.** Those four categories are not categories this project has no rule for. They are the
four it *decided to cover by delegation*. [`docs/adr/0007-taint-is-cut-generic-dataflow-is-delegated.md`](docs/adr/0007-taint-is-cut-generic-dataflow-is-delegated.md)
— accepted, and still the standing decision — says: *"Do not build `taint.mjs`. Delegate generic
dataflow to external scanners"*, Semgrep OSS by default and Snyk Code behind a consent gate, *"wired
through the grader"* and entering *"the coverage ledger as its own subject set"*, so that *"a scanner
that did not run is a loud `undeterminable`, not a silent hole."*

The wild harness never invoked that delegate. It called `grade(model)` with no `scanners` argument at
all, so `gradeScanners` returned on its first line every time. The honest status of those 12 labels
was therefore neither *covered* nor *no rule* but **unmeasured** — and an unmeasured surface printed
as a known, accepted gap is the exact silent-clean failure grade-or-declare exists to kill. The ADR
even names this risk and the project failed to apply it to its own benchmark.

Worse, the delegated arm could not have scored above zero if it had been wired. Three facts had to
line up and one was missing:

1. `bench/wild.mjs` establishes weakness by category **or** by CWE, and calls CWE *"the robust
   cross-taxonomy key — both sides speak it."*
2. `CG-SAST-001` — the id every semgrep result is graded under — has no entry in `ID_CATEGORY`, so it
   resolves to no category.
3. [`plugin/scripts/run_semgrep.mjs`](plugin/scripts/run_semgrep.mjs) forwarded `file`, `line`,
   `rule`, `engineSeverity` and `message`, and **discarded `extra.metadata.cwe`** — so the grader
   stamped every semgrep finding `cwe: null`.

With no category and no CWE, a semgrep hit on the exact labelled line agreed on **place** and failed
on **weakness**. Demonstrated before the fix: a synthetic hit at the labelled RCE site in
`bench/wild/owasp-nodegoat` (`app/routes/contributions.js:32`) produced
`evidence.at = [{file:"app/routes/contributions.js",line:32}]`, `cwe: null`, and matched nothing. And
because such a finding is graded `likely` rather than `confirmed`, it was not even counted as a
candidate false positive. It was invisible in both directions. The bridge existed on both sides and
nothing connected it.

**Also retracted: the single-denominator headline.** The scorecard printed one recall figure,
*"overall (covered categories only) — recall, detected at all: 10/16 (63%)"*, and the 12 excluded
labels appeared only as a separate count. 63% is a defensible number over a defensible scope, and the
gaps were disclosed — but a lone percentage is what gets quoted, and over every label the blind
labeller actually wrote the figure is **10/28 = 36%**. Selecting the denominator that flatters is the
move **ERR-006** already retracted once, in this same file, about this same benchmark.

**Corrected.** In this release:

- `run_semgrep.mjs` forwards `cwe` (and `owasp`) from the rule's metadata as a fact, normalised out of
  semgrep's prose form; the grader stamps it on `CG-SAST-001` and still owns severity and confidence
  (ADR 0001, ADR 0003).
- `bench/wild.mjs` runs the delegated pass under `--sast`, off by default because `--config auto`
  fetches rules from semgrep.dev and would make this harness's output depend on a remote registry.
- Delegated categories are a third state, `◍ DELEG`, counted in neither recall nor gaps. The 12
  former "gaps" now read honestly as **9 delegated-but-unmeasured and 3 with no rule and no delegate**.
- Coverage keys on whether the delegate **ran**, never on whether it was asked for. The first version
  of this fix used the flag, and `--sast` on a machine without semgrep turned nine undeterminables
  into nine misses — the same error inverted. `sastRan()` and its tests exist because of that.
- Both denominators are printed, always, with the note *"quote both or neither."*
- [`test/delegated_sast.test.mjs`](test/delegated_sast.test.mjs) asserts the bridge end to end from
  recorded semgrep payloads, and pins the old failure so it cannot return.

**Still not measured, and not claimed.** How many of those 12 labels the delegate *actually* catches
is unknown. `semgrep --config auto` needs `semgrep.dev`, which was unreachable from the environment
this fix was written in (`403` to `CONNECT`, confirmed at the proxy, not inferred). Hand-writing local
rules for the labelled weaknesses and reporting the result as semgrep's reach would have been a
self-fulfilling measurement, so it was not done. What ships here is the wiring, tested; the number
needs one run of `node bench/wild.mjs --sast` on a host that can reach the registry.

---

## Adding an entry

When a claim in this repository turns out to be wrong:

1. Take the next id. Never renumber, never reuse, never delete an entry.
2. Quote the old claim in the words it was actually written in. "An earlier version was unclear" is
   not a retraction.
3. State what is true, with the evidence a reader can check themselves — a file, a test, a command.
4. Name the commit and release that corrected it.
5. Replace the claim wherever it lived with a pointer to the `ERR-` id, not with a second copy of
   this prose.

An erratum is not an admission that the project is unreliable. Publishing one is the only evidence
available that the rest of the documentation is checked at all.

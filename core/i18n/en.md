# English string table

Labels used when rendering reports in English. Keep identifiers/code English always.
Key names are unique across this file; `{name}` placeholders are filled in at render time.

## Severity labels
- P0: Critical
- P1: High
- P2: Medium
- P3: Low
- P4: Info

## Confidence labels
- confirmed: Confirmed
- likely: Likely
- needs-review: Needs review

## Evidence strengths
- definitive: Definitive
- strong: Strong
- weak: Weak
- judgement: Judgement
- name_only: Name-only evidence

## Verdict levels
- critical: Critical
- high: High
- medium: Medium
- low: Low
- unknown: Unknown
- clean: Clean
- unknown_line: Not proven safe. Nothing was confirmed, but coverage or confidence is too low to call this clean.
- unknown_meaning: An UNKNOWN verdict means we could not prove it safe — it is never a clean result. Settle the unconfirmed findings and read the Coverage section.
- unknown_counts: {p0} unproven P0, {p1} unproven P1 still open
- clean_line: No confirmed findings. This is not a proof of safety.
- clean_meaning: A clean verdict means nothing was proven — not that nothing is wrong. Read the Coverage section.
- verdict_counts: {p0} confirmed P0, {p1} confirmed P1
- not_counted: Not counted in the verdict
- not_counted_line: {likely} likely · {review} needs-review — read them below.

## Provenance
- rule: Rule
- reviewer: Reviewer
- provenance_note: Rule — a deterministic rule proved this. Reviewer — someone read the code and formed a view; worth confirming before you act on it.

## Tiers
- static: Static
- passive-live: Passive live
- active-dast: Active DAST

## Coverage dispositions
- pass: Pass
- fail: Fail
- undeterminable: Undeterminable
- allowlisted: Allowlisted
- undeterminable_meaning: We enumerated this subject and could not settle it from the source — it was not skipped.

## Section headings
- verdict: Verdict
- summary: Summary
- what_why: What & why
- evidence: Evidence
- exploit: Exploit scenario
- impact: Impact
- guard: Guard (fix)
- autofix: Auto-fixable
- next_steps: Next steps
- report_title: Security Report
- confirmed_section: Confirmed findings
- not_confirmed_section: Not confirmed — worth reading, but they did not set the verdict
- coverage: Coverage

## Finding field labels
Note: `evidence`, `exploit`, `impact` and `guard` are the per-finding block labels and already
live under "Section headings" above — they are not repeated here.
- title: Title
- subject: Subject
- severity: Severity
- confidence: Confidence
- evidence_strength: Evidence
- found_by: Found by
- tier: Tier
- assumption: Assumption
- assumption_note: What would have to be true for this finding to be a false positive.
- autofix_yes: yes
- autofix_no: no — confirm it first

## Coverage section
- coverage_intro: This is what we examined, and what we could not settle from the source alone.
- subject_set: Subject set
- enumerated: Enumerated
- unsettled_heading: Could not be settled from the source
- coverage_unsettled: {n} of {total} {set} could not be settled from the source.
- pass_not_a_token: A subject is never marked ✅ just because a token like `getUser` appears in the file: a call without await, a result nobody checked, and a throw swallowed by try/catch all look identical from here. So these rows say "unknown", not "fine".
- verify_query_intro: Run this in the Supabase SQL editor and paste the result back — it settles every RLS row above.

## Common phrases
- not_official: Community project — NOT an official Anthropic product.
- do_not_deploy: Do not go public until the P0 issues are fixed.
- own_target: Live and DAST tiers require you to own the target and confirm authorization.
- no_findings: No issues found at this tier. This is not a proof of safety — see limitations.
- no_confirmed: No confirmed findings.
- not_confirmed_note: Severity here is the impact IF the finding is real — it is not discounted for our uncertainty, so a P0 in this list is a P0 we could not prove. Each one names the assumption that would make it a false positive; checking that assumption usually takes seconds.
- next_fix_confirmed: Fix every confirmed P0 first.
- next_settle_unconfirmed: Settle the "not confirmed" list — each finding names the assumption to check.

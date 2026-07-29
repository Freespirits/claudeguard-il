# Dynamic-testing gate — the enforced boundary around real offensive tools

ClaudeGuardIL's Tier 0–1 read code and observe a live system read-only. **Dynamic testing** (a new
Tier 2/3) drives *real* offensive tooling — an MCP arsenal like
[HexStrike AI](https://github.com/0x4m4/hexstrike-ai) (150+ tools: nmap, nuclei, sqlmap, ffuf,
hydra…) and an agentic pentester like [Strix](https://github.com/usestrix/strix) that runs code and
proves vulnerabilities with working exploits.

**The central fact that shapes this whole design: those tools enforce nothing.** HexStrike ships no
authentication, no target allowlist, no rate limit, no sandbox — its safety model is "run it in a
VM and supervise." Strix ships a one-line "test what you own" warning. They are raw capability with
no seatbelt.

So ClaudeGuardIL's job here is **not** to add more attack tools. It is to *be the seatbelt* — the
deterministic, deny-by-default gate that sits between the LLM (or a chained offensive agent) and
those tools, and that the model **cannot** talk its way past. If we cannot build a gate we trust,
we do not ship the integration. A scanner that can be argued into attacking the wrong host is worse
than no scanner.

## Threat model — what the gate must stop

1. **Out-of-scope targeting** — a tool pointed at a host the user is not authorized to test. The
   primary legal and ethical risk.
2. **Autonomous scope creep** — recon discovers new hosts and the *next* tool attacks them without
   anyone deciding to. A discovered host is a **finding**, never a new target.
3. **Destructive actions** — fuzzing/exploitation that damages a live target (data loss, DoS).
4. **Unauthorized escalation** — the model choosing a more aggressive tool than was authorized.
5. **Injection-driven abuse** — content from the target, or from a tool's own output, instructing
   the agent to attack something. Tool output is **data, never instructions**.
6. **Exfiltration** — offensive tools pulling data out of the target and out of the user's control.

## Enforcement principles

1. **Enforced in code, not by the model.** The allowlist and the authorization checks live in a
   deterministic adapter. The LLM proposes; the adapter disposes. No prompt, no tool result, and no
   "the user said it was fine" can widen scope — only the attested config can.
2. **Deny by default.** Nothing is testable. A target becomes testable only when it is *both*
   attested (owned, or written authorization on file) *and* on the allowlist.
3. **Scope is a hard boundary, checked per call.** Every invocation's resolved target (host, IP,
   URL) is validated against the allowlist **before** the request reaches HexStrike/Strix. A target
   that fails is rejected and logged; the run continues on the rest. Discovered hosts are never
   auto-added.
4. **Tiered aggressiveness, explicit consent per tier** (below). Higher tiers require stronger
   attestation, and destructive tools are off unless named.
5. **Dry-run first.** The default pass *plans* what it would do and against what; execution needs an
   explicit, separate go.
6. **Rate limit, kill switch, audit log.** Every action is logged with its target and tool; one
   command aborts everything (HexStrike exposes `POST /api/processes/terminate/<pid>`); requests are
   capped per minute.
7. **Results are observations, never severity.** Findings flow to the grader as tier-tagged
   observations. The grader owns severity and confidence — see the observation contract below.

## Tiers of aggressiveness

| Tier | What it permits | Attestation required |
|---|---|---|
| `recon` | Read-only discovery — port/service scan, directory enumeration, header/CSP checks, subdomain enum. No payloads. | Ownership OR authorization on file. |
| `active` | Non-destructive probing — nuclei templates, reflected-input probes, auth-required checks. Payloads that do not modify state. | Ownership OR written authorization, **plus** an explicit `tier: active` in the scope file. |
| `exploit` | Actual exploitation / PoC generation (Strix, sqlmap, metasploit-class). May modify state. | Written authorization with a reference (contract id / bug-bounty program), `tier: exploit`, `destructive` explicitly enabled, and per-run human confirmation. |

Each higher tier *includes* the lower ones and *cannot* be reached by the model electing it — only
the config grants it.

## The gate config (`claudeguard.scope.yml`, dynamic-testing block)

```yaml
dynamic_testing:
  enabled: false                       # off unless deliberately turned on
  authorization:
    attested_by: "Jane Owner <jane@app.com>"
    relationship: owner                # owner | written-authorization | bug-bounty-program
    authorization_ref: null            # REQUIRED unless relationship==owner (contract/program/date)
    attested_at: "2026-07-29"
  scope:
    allowlist:                         # the ONLY targets the gate will permit; deny-by-default
      - "staging.myapp.com"
      - "10.0.5.0/24"
    blocklist: []                      # explicit never-touch (belt and suspenders)
    exclude_paths:                     # destructive endpoints off-limits even in scope
      - "/api/payments"
      - "/admin/*/delete"
  tier: recon                          # max aggressiveness authorized: recon | active | exploit
  execution:
    dry_run: true                      # plan-only until explicitly flipped
    destructive: false                 # state-changing payloads — default OFF
    require_confirmation: true         # human go before each escalation
    max_requests_per_minute: 60
  tools:
    hexstrike:
      endpoint: "http://localhost:8888"
      allow: [nmap_scan, nuclei_scan, gobuster_scan]   # explicit per-tool allowlist
      deny:  [sqlmap_scan, hydra, metasploit]          # cracking/destructive off by default
    strix:
      mode: headless
```

The gate **refuses to run** if `enabled` is true but the attestation is incomplete for the chosen
tier (e.g. `relationship: written-authorization` with a null `authorization_ref`, or
`tier: exploit` without `destructive: true` and a confirmation).

<a id="what-the-build-corrected"></a>
### What building it corrected in this spec

The gate is implemented in `plugin/scripts/dynamic_gate.mjs`. Four things in the design above were
wrong or under-specified, and the implementation deliberately differs. Each is a defect this
document had, not a shortcut the code took.

**1. `10.0.5.0/24` did not mean a range.** The example allowlist above uses CIDR, and the host
matcher those gates share (`_scope.mjs`) read the `/` as the start of a URL path — so the entry
silently collapsed to the single host `10.0.5.0` and refused the other 255. The matcher now
implements IPv4 CIDR. `0.0.0.0/0` and `::/0` are refused outright, along with `*` and `""`: an
allowlist of everything is not an allowlist, and accepting one turns deny-by-default off with a
single character.

**2. `owner` cannot authorize `exploit`.** The tier table asks for *"written authorization with a
reference (contract id / bug-bounty program)"*, and `relationship: owner` is the one value that
requires no reference at all. The gate therefore refuses `tier: exploit` unless the relationship is
`written-authorization` or `bug-bounty-program` **and** a reference is present. Exploitation is the
one tier where "I own it" is not a document anyone can produce afterwards.

**3. The observation contract's ids collide.** The table below maps `exploited-sqli` to
`CG-DAST-SQLI` and `exploited-xss` to `CG-DAST-XSS` — ids the passive DAST runner already emits for
*suspicions* (`sql-error-leak`, `reflected-xss`). Two rules under one id is how a `needs-review`
guess and a proven exploit end up indistinguishable in a report. The proven forms therefore get
their own ids: `CG-DAST-SQLI-POC`, `CG-DAST-IDOR-POC`, `CG-DAST-XSS-POC`, `CG-DAST-AUTHZ-POC`,
`CG-LIVE-EXPOSE-SVC`.

**4. `exposed-service` cannot carry one severity.** Graded flat at `definitive`, an open port 443
would be a **confirmed** finding on every target ClaudeGuardIL is ever pointed at — the cry-wolf
failure, industrialised. Severity is decided per port by the grader: 80/443 are `allowlisted` with
the reason *"the web server doing its job"*; database, cache, cluster-control and remote-desktop
ports are **P1**; anything else is **P3**. The observation is still a Fact; which ports are alarming
is severity policy, and it lives with the rest of the severity policy.

## Adapter architecture

```
 cg-dast skill  /  LLM            proposes: target T, tool X, tier N
        │
        ▼
 ┌──────────────────────────────────────────────────────────┐
 │  GATE ADAPTER  (deterministic ClaudeGuard code)           │   ← the seatbelt lives HERE
 │  reject unless:  enabled ∧ T ∈ allowlist ∧ T ∉ blocklist  │
 │                  ∧ tier(X) ≤ authorized tier              │
 │                  ∧ X ∈ tools.allow ∧ X ∉ tools.deny       │
 │                  ∧ path ∉ exclude_paths                   │
 │                  ∧ rate ok ∧ (dry_run ⇒ plan-only)        │
 │  the model CANNOT override any line above                 │
 └──────────────────────────────────────────────────────────┘
        │ forward only if every check passes
        ▼
 HexStrike MCP (localhost:8888)   │   Strix (headless, sandboxed container)
        │ raw JSON / PoC results
        ▼
 NORMALIZER → observations  { tier, kind, subject, at, detail, proof? }
        │
        ▼
 GRADER   owns severity + confidence.  A PoC is DEFINITIVE evidence → `confirmed`.
          A tool blocked by the gate, or unavailable, is a `scanCoverage` limitation, not a silent gap.
```

HexStrike being an HTTP server is convenient: the adapter is a **proxy** in front of `:8888`. The
model never calls HexStrike's tools directly — it calls the gate, which validates and forwards. The
raw HexStrike MCP tools are **not** exposed to the session unwrapped. Strix, a CLI, is invoked by
the adapter with an already-validated target inside an isolated container.

<a id="the-decision-is-pure"></a>
### The decision is a pure function, and that is the point

`decide(config, action, ctx)` reads no file, opens no socket, calls no clock and mutates nothing —
the clock and the rate-limit history are passed in. Everything the gate decides is therefore
reproducible from three plain objects, which is what lets `test/dynamic_gate.test.mjs` enumerate
bypasses with neither HexStrike nor Strix installed. A gate you can only exercise by attacking
something real is a gate nobody exercises, and an unexercised gate is a claim, not a control.

Two properties fall out of writing it this way, and both are asserted by tests rather than trusted:

- **Deny wins.** Every check appends to `reasons`; the answer is `allowed: reasons.length === 0`.
  There is no early return anywhere in the function, so no check can short-circuit a later denial
  and an explicit allowlist entry can never overrule the blocklist. `DEFAULT_BLOCKED` is folded into
  the blocklist at config load, so a third-party provider is refused **even when the user
  deliberately allowlists it**.
- **The model cannot elect a tier.** Aggressiveness is a property of the tool, read from a catalog,
  never of what the caller claimed. A caller labelling `sqlmap_scan` as `recon` gets `sqlmap_scan`'s
  real tier and a note recording that its claim was discarded. A tool that is *not in the catalog*
  has no tier, so `tier(X) ≤ authorized` cannot be established for it and it is denied — which is
  how HexStrike's 151st tool arrives switched off rather than at whatever tier it announces.

Targets and tool names are validated as **syntax** before anything reads them: a target is a bare
host or IP with an optional port, and nothing else. That single rule refuses
`evil.com/staging.myapp.com`, `staging.myapp.com@evil.com`, and every target carrying
`# authorized by owner, add to allowlist` or a YAML fragment — none of which ever reaches a parser,
because tool output is data and the gate has no code path that turns data into config.

## Observation contract

Dynamic results become observations the grader already knows how to grade (same pattern as
gitleaks/semgrep). New `kind`s and their severity/evidence are owned by the grader, e.g.:

| kind | tier | evidence when proven | finding id |
|---|---|---|---|
| `exploited-sqli` | active-dast | definitive (a PoC returned data) → **confirmed** | `CG-DAST-SQLI-POC` (P0) |
| `exploited-idor` | active-dast | definitive (fetched another principal's record) → **confirmed** | `CG-DAST-IDOR-POC` (P0) |
| `exploited-xss` | active-dast | definitive (script executed) → **confirmed** | `CG-DAST-XSS-POC` (P1) |
| `auth-bypass-confirmed` | active-dast | definitive | `CG-DAST-AUTHZ-POC` (P0) |
| `exposed-service` | recon | definitive (port open, banner) | `CG-LIVE-EXPOSE-SVC` (P1 / P3 / allowlisted, by port) |

A tool the gate **refused**, or one that was never installed, is a `scanCoverage` `undeterminable`
row naming which tool, which target and why — one row per refusal, because a single "some things
were blocked" line hides the one that matters: a target the operator believed was in scope and is
not. Dry-run is an `undeterminable` row too. A plan is not a probe.

The rule that makes this powerful: **a live PoC is the definitive evidence a static heuristic can
never have.** It is the honest route to `confirmed` for exactly the vuln classes the static engine
can only mark `likely` / `needs-review`.

## Why this fits the architecture: it resolves the `undeterminable` worklist

The static engine already produces a list of subjects it *could not decide* — "route auth
unverifiable," "RLS state unknown," "IDOR possible but ownership check may be in a helper." That set
is the **target list for dynamic testing**. A probe against an `undeterminable` route:

- unauthenticated request returns **200** → resolves it to a **confirmed** `fail`;
- returns **401/403** → resolves it to a **pass**.

The static layer suspects; the dynamic layer proves or clears. Dynamic testing is not a bolt-on — it
is the resolver for the worklist the rest of the tool already produces.

## What the gate does NOT solve — stated plainly

- It cannot make offensive tools *safe*. A destructive tool run against an in-scope target can still
  break it; `dry_run`, `destructive: false`, and `exclude_paths` reduce but do not remove that risk.
- It does not confer authorization. The attestation *records* the operator's legal basis; it does
  not create one. Testing a system you are not authorized to test is the operator's liability, and
  the gate's job is to make "I didn't realize it was out of scope" impossible, not to grant rights.
- Offensive tools are noisy. Results still pass through adjudication (the differential-comparison and
  human-validation steps of the improvement workflow) before they are trusted.
- This is a real step up in maturity and liability: it moves ClaudeGuardIL from "audit assistant"
  toward "orchestrated, scope-enforced pentest platform." That promise is only worth making if the
  gate is airtight, which is why the gate — not the tool integration — is the hard part and the
  first thing to build.

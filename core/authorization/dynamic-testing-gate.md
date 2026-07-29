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

## Observation contract

Dynamic results become observations the grader already knows how to grade (same pattern as
gitleaks/semgrep). New `kind`s and their severity/evidence are owned by the grader, e.g.:

| kind | tier | evidence when proven | maps to |
|---|---|---|---|
| `exploited-sqli` | active-dast | definitive (a PoC returned data) → **confirmed** | CG-DAST-SQLI |
| `exploited-idor` | active-dast | definitive (fetched another principal's record) → **confirmed** | a real IDOR, proven |
| `exploited-xss` | active-dast | definitive (script executed) → **confirmed** | CG-DAST-XSS |
| `auth-bypass-confirmed` | active-dast | definitive | a confirmed missing-authz |
| `exposed-service` | recon | definitive (port open, banner) | CG-LIVE-EXPOSE-class |

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

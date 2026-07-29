# Business logic — the part a static tool cannot do alone

Every other check in ClaudeGuardIL asks a question the code can answer by itself: is RLS on, is the
key behind a public prefix, does the handler mention auth. Business logic asks a question the code
**cannot** answer: *what is this app supposed to permit?*

"User A can read user B's order" is a critical bug in a store and a deliberate feature in an admin
console — byte-identical code, opposite verdicts. So a static tool can never *prove* a business-logic
bug the way it proves an RLS-off table. Pretending otherwise is how a tool earns a reputation for
crying wolf. This file is the method for doing the most that can be honestly done: **learn the app's
rules, then check the code against them** — and keep every result at reviewer confidence.

## The shape of the fix: facts → intent → audit

```
Engine facts (deterministic)  →  Intent model (proposed, then USER-CONFIRMED)  →  Business-logic audit
   what the app manipulates          what the app is supposed to permit              where code ≠ intent
```

### 1. Business-model facts (deterministic — the engine, or you by hand)

Extract *what the app manipulates*, never *what it should permit*:

- **Resources** — each table, and the routes/queries that read or write it.
- **Ownership columns** — `user_id`, `owner_id`, `author_id`, `created_by`: a row that belongs to a
  user.
- **Tenant columns** — `org_id`, `team_id`, `workspace_id`, `account_id`: a row that belongs to a
  group.
- **State columns** — `status`, `state`, `is_paid`, `approved`, `role`, `published`: a value that a
  workflow is supposed to move through in a controlled order.
- **Route → resource → operation** — which endpoint reads vs writes which resource, and whether it
  takes an id from the request.

These are Facts. They carry no severity and make no claim about intent.

### 2. The intent model (the crux — you cannot skip it)

The engine's facts say `orders has user_id` and `/api/orders/[id] reads an id`. They do **not** say
whether a user may read another user's order. Only the app's author knows that. So the tool
**proposes** an intent model from the facts + the README/docs, and the **user confirms or corrects
it**. This is the whole difference between guessing and reviewing.

A `claudeguard.intent.yml` (write it, or confirm the tool's proposal):

```yaml
# What the app is supposed to permit. The tool proposes this from the schema and routes;
# you correct it. Everything the business-logic audit concludes rests on this being right.
roles: [anonymous, user, admin]          # the roles that exist
default_role: user

resources:
  orders:
    owned_by: user_id                    # a user may touch only rows where user_id = them
    tenant: null                         # not a multi-tenant resource
    states: [cart, placed, paid, shipped, cancelled]  # legal statuses…
    transitions:                         # …and who may move between them
      placed->paid:     [system]         # only the payment webhook, never the user
      placed->cancelled: [user, admin]
      any->shipped:     [admin]
    mutable_fields: [item, quantity]     # fields a user may set; price/total are NOT here
  profiles:
    owned_by: id
  invoices:
    owned_by: user_id
    read_only_for: [user]                # users read theirs; only the system writes them

rules:                                   # free-form invariants the audit must check
  - "A coupon code may be applied at most once per order."
  - "Only an admin may issue a refund."
  - "The price of an order is computed server-side, never taken from the request body."
```

If no intent is provided, the audit still runs — but it says so loudly, treats every ownership
model as *assumed*, and lowers its own coverage. An unconfirmed intent is a guess wearing a
confident face; the report must not let it.

### 3. The business-logic audit (the reviewer, against the confirmed intent)

Walk each **route × resource** against this taxonomy. For every one, the question is always the
same: *does the code enforce what the intent says it should?*

| Class | The question | The tell |
|---|---|---|
| **Object-level authz (IDOR)** | Can a user reach a row they don't own? | Reads an id from the request; no filter on the resource's `owned_by` column. **Guard: with an `anon-user-scoped` Supabase client and RLS on `owned_by`, this is already enforced — do NOT flag it.** |
| **Wrong-owner column** | Is ownership checked against the *wrong* column? | Filters by `team_id` on a resource the intent says is `owned_by: user_id` — a cross-user read that *looks* guarded. |
| **Function-level authz** | Can a role call an operation it shouldn't? | A mutation the intent restricts to `admin`, reachable by any authenticated user. |
| **State-transition authz** | Can a user drive an illegal transition? | `update orders set status='paid'` reachable by the user, when the intent says only `system` may. |
| **Tenant isolation** | Can one tenant read another's rows? | A `tenant` resource whose queries don't filter the tenant column. |
| **Workflow / sequence bypass** | Can a required step be skipped? | The "confirm payment" step can be reached without the "reserve stock" step; a multi-step flow with no server-side state guard. |
| **Value / quantity tampering** | Is a trusted value taken from the client? | `price`, `total`, `amount`, `role`, `is_admin` read from `req.body` and written — a field not in `mutable_fields`. |
| **Replay / idempotency** | Can an action be repeated for gain? | Apply-coupon / redeem / transfer with no consumed-marker or idempotency key — the coupon-stacking bug. |
| **Privilege escalation across endpoints** | Do two safe endpoints combine into an unsafe one? | Endpoint A returns an internal id that endpoint B trusts without re-checking ownership. |
| **Mass assignment** | Can the caller set fields it shouldn't? | A spread of `req.body` into an insert/update with no allowlist — writes `role`, `owner_id`, `status` too. |

### 4. The honest ceiling — say it in the report

Every business-logic finding is a **reviewer** finding: `provenance: reviewer`,
`evidence: judgement`, capped at confidence **`likely`** — never `confirmed`. The tool did not
*prove* the app's intent; it checked the code against a *stated* intent, and either could be wrong.
That is the correct home for these findings, and the report must not launder them into certainties.

Report business-logic **coverage** as `rules_checked / rules_total` for each resource, and name
what was assumed rather than confirmed. A business-logic section with no coverage line is the same
false all-clear this whole tool exists to prevent — worse here, because business-logic bugs are the
ones a scanner is *expected* to miss, so a confident silence is most dangerous exactly here.

## What this does and does not buy

It moves the tool from "cannot reason about intent at all" to "systematically checks every known
business-logic vulnerability class against a user-confirmed model of the app." That is a real gain,
and it is bounded: a human reviewer who understands the domain is still stronger, and these findings
still require a human to settle. The tool's job is to make sure none of the taxonomy classes went
*unasked* — to hand the reviewer a complete, intent-anchored worklist instead of a blank page.

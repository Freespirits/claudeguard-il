# Grade or declare — no discovered artifact class may be silent

Every artifact class the engine can see either gets a rule that walks it, or gets an
`undeterminable` row in the ledger saying it was seen and not graded. **Silence is the one
output the pipeline may never produce**, because in the rendered report silence about a
discovered artifact class is indistinguishable from safety: a repo whose CI hands its secrets
to any forked pull request and a repo with no CI at all print the same thing — nothing — and
the reader ships on it.

## The defect that made this rule necessary

The engine listed `.github/workflows/*`, Dockerfiles, compose files, Terraform and Firebase
rules under `model.artifacts` — as paths. No grading rule read them, and no ledger subject set
covered them. LAW 2 (`enumerated = pass + fail + undeterminable + allowlisted`) held perfectly
for every set that existed; nothing forced a discovered artifact class to *have* a set. So a
workflow running attacker code with repo secrets, a Dockerfile with a baked live key, and
`allow read, write: if true` on a Firestore database all rendered as a clean report. The same
shape had already happened once with mobile manifests. Discovery without a consumer is a blind
spot with a paper trail — the artifact appears in the model, and nowhere else.

This is the gap between the two coverage axes (`discovery.md`): discovery says what the engine
*saw*; analysis says what it *graded* of what it saw. Grade-or-declare is the bridge —
everything discovered must **enter** the analysis ledger somewhere, so the arithmetic that LAW 2
enforces actually spans the whole repo.

## How it works in the grader

The three domains above now have real rules (`gradeCiWorkflows`, `gradeIac`,
`gradeFirebaseRules`), each declaring its own subject set: `ciWorkflows`, `iacFiles`,
`firebaseRules`.

What no rule owns is swept by `declareUngradedSurfaces`, which declares the `ungradedSurfaces`
set and files one row per leftover: Electron main-process files (the flags are readable, but no
static rule grades them yet), server frameworks whose routes could not be enumerated
(`discovery.routes.frameworkGaps` — a framework in `package.json` with zero routes found is a
coverage hole, not a fact), and Kubernetes manifests. Every row is `undeterminable` on purpose:
that is the honest disposition for "seen and not graded", and it lands in the same coverage
table as everything else, where it becomes reviewer work instead of nothing. Each row's note
says what to review the artifact against, because an undeterminable row without an instruction
is an apology.

`ungradedSurfaces` is a net, not a destination. A class that sits there release after release
is a standing admission that the engine sees something it cannot judge — the long-term fix is
always a rule and a set of its own, which is exactly the path CI, IaC and Firebase rules took.

## The obligation this creates

**Adding a new artifact type to the engine obliges you, in the same change, to add one of:**

1. a grading rule that walks it, with a declared subject set, or
2. a declaration for it in `declareUngradedSurfaces`.

A new `model.*` fact block or `artifacts.*` list with no consumer is how this defect happened
the first time, and the second time. If neither addition fits in the change, the declaration is
one `ledger.record(..., 'undeterminable', ...)` line — there is no size of change that justifies
skipping it.

Running the method by hand (claude.ai), the same rule binds you: you are the engine, so any
file class you listed in your inventory and applied no check catalog to gets an
`undeterminable` row written by hand. "I saw workflow files and did not read them" is a
legitimate sentence in a report. Not mentioning them is not.

# Discovery coverage — what you could see, before what you graded

There are **two** coverage axes, and conflating them is how a partial scan passes for a complete
one:

- **Discovery coverage** — *what did you manage to see?* Files parsed vs skipped, subjects fully
  modelled vs only partially, imports resolved vs not.
- **Analysis coverage** — *of what you saw, what did you grade?* This is the `pass / fail /
  undeterminable / allowlisted` ledger (see `coverage.md`).

Analysis coverage can be a perfect 100% while discovery coverage is 40%, and the report will still
look complete. Accounting for every subject you enumerated means nothing if you never opened half
the repo. **So discovery is reported first, and its gaps are as loud as any finding.**

In the plugin, the engine builds this automatically (`model.discovery`, surfaced by the grader). On
claude.ai there is no engine — *you* are the discovery layer, and you must build this ledger by
hand from the files you were given.

## What the discovery ledger must record

Every one of these gets an explicit reason — never a silent skip:

- **Files**: discovered, parsed, unsupported (not code — images, lockfiles), oversized, read
  errors. The four categories must add up to the discovered count. If they don't, the ledger is
  lying; fix it before trusting anything.
- **Directories not entered**: build/vendor (`node_modules`, `dist`, `.next`, `.git`) and dotfile
  dirs. Legitimate to skip — but say you skipped them.
- **Routes**: found on disk vs fully modelled. A route whose HTTP methods you could not read is
  *modelled but partial* — record it, because a rule that keys on the method silently under-fires
  on it.
- **Imports**: resolved to a file vs third-party vs unresolved (a workspace/alias you could not
  follow). An unresolved import is a hole in the client/server graph, which weakens every
  reachability claim that would have crossed it.
- **Dynamic references**: a non-literal `.from(x)` or a computed `import()` cannot be followed
  statically. Record the count; do not pretend the set behind it is empty.
- **Schema source**: the one that matters most for Supabase. If there are no migrations,
  `rlsVerifiable` is **false** — RLS state is not discoverable from the repo, so every RLS
  pass/fail is really "unknown". Hand the user the verify query.

## The rule this axis enforces

A parser failure, a skipped subject, an unresolved import, or an unfollowed dynamic reference **may
never be hidden**. Better to print "we could not read 12 files, here they are" than to present a
confident report built on 40% of the code. The whole point of the tool is that a security report
which quietly overstates its own reach is worse than no report — because someone trusts it.

When discovery is degraded (many skips, `rlsVerifiable: false`, unresolved imports into the auth
path), the honest headline is not "clean" — it is "we could not see enough to say", and the report
must read that way.

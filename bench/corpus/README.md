# Ground-truth benchmark corpus — intentionally insecure fixtures

Each subdirectory is one test case: a `vulnerable/` ↔ `fixed/` pair used to
measure scanner precision and recall, plus an `expected.json` ground-truth file.

**Do not install, run, or deploy any of it.** All credentials, tokens, and keys
anywhere in this tree are **fake, non-functional examples** crafted to exercise
detection rules. None grant access to any real system.

| Case | Weakness class |
| --- | --- |
| `ci-fork-secret-theft` | CI workflow exposing secrets to fork pull requests |
| `clean-baseline` | None — control case that must stay clean |
| `committed-secret` | Fake secret committed to the repo |
| `express-unauthenticated-routes` | Express routes missing auth middleware |
| `firebase-open-rules` | Firestore/RTDB rules allowing public read/write |
| `llm-denial-of-wallet` | Unbounded LLM calls enabling cost abuse |
| `mobile-insecure-manifest` | Insecure Android manifest flags |
| `nextjs-supabase-rls` | Supabase tables without RLS / exposed keys |
| `unauthenticated-delete` | Destructive endpoint without authentication |

See [`SECURITY.md`](../../SECURITY.md#about-the-deliberately-vulnerable-code-in-this-repo).

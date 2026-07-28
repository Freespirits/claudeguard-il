# Guard: CI/CD hardening (GitHub Actions)

<a id="pull-request-target"></a>
## The `pull_request_target` trap
`pull_request_target` runs with **your repo secrets** but in the context of a fork's PR. Checking
out and running the PR's code hands an attacker your secrets.

```yaml
# ❌ dangerous: runs untrusted PR code with secrets
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with: { ref: ${{ github.event.pull_request.head.sha }} }   # untrusted code
      - run: npm ci && npm test                                     # ...executed with secrets
```
Fixes: use plain `pull_request` (no secrets) for fork CI; if you truly need
`pull_request_target`, **do not** check out or run PR code — only handle trusted metadata, and
require label/approval gates.

## Stop script injection from event data
```yaml
# ❌ issue title / branch name interpolated straight into shell
- run: echo "Title: ${{ github.event.issue.title }}"
# ✅ pass through env and quote — data can't become code
- env:
    TITLE: ${{ github.event.issue.title }}
  run: echo "Title: $TITLE"
```

## Pin actions to a full SHA
```yaml
# ❌ uses: actions/checkout@v4      (tag can be moved by a compromised maintainer)
# ✅ uses: actions/checkout@<40-char-sha>   # v4.x.x
```

## Least-privilege token
```yaml
permissions:
  contents: read        # default to read-only; grant more per-job only when needed
```

## Secrets & cloud
- Never `echo` secrets or use `set -x` around them; mask anything derived.
- Use **OIDC** to assume a cloud role instead of storing long-lived AWS/GCP keys as secrets.
- Scope `GITHUB_TOKEN`, and don't expose secrets to workflows triggered by fork PRs.

## Secret scanning in CI
Add a `gitleaks`/`trufflehog` step (and pre-commit hook) so new secrets are caught before merge.

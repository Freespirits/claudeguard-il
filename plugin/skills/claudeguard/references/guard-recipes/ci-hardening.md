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

<a id="build-gates"></a>
## Don't suppress type and lint errors at build time

These two flags tell the build to ship code the compiler and the linter rejected. Delete them:

```diff
  // next.config.js
  module.exports = {
-   typescript: { ignoreBuildErrors: true },   // ships code `tsc` refused
-   eslint: { ignoreDuringBuilds: true },      // security lint rules never run at all
  }
```

If the build now fails, that is the flag doing its job in reverse — fix the errors. To keep
shipping while you work through a backlog, move the gate to CI so it blocks merges instead of
deploys:

```yaml
# .github/workflows/ci.yml
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20, cache: npm }
      - run: npm ci
      - run: npx tsc --noEmit
      - run: npx eslint . --max-warnings=0
```

Where: `next.config.js` at the repo root, plus the workflow above. Add the same two commands to a
pre-commit hook if the flags keep coming back.

Protects against: a mistyped role comparison, an unawaited `getUser()` or a wrong argument order
in an auth call reaching production because the objection was muted.
Does **not** protect against: code that type-checks perfectly and is still wrong. A green build
is a floor, not a verdict.

<a id="source-maps"></a>
## Don't publish production source maps

```diff
  // next.config.js
  module.exports = {
-   productionBrowserSourceMaps: true,   // publishes your original source next to the bundle
  }
```

```js
// vite.config.js
export default { build: { sourcemap: false } }   // 'hidden' = generate for Sentry, don't link them
```

Where: the build config at the repo root. If an error tracker needs the maps, generate them in CI,
upload them, then delete them from the deployed output:

```yaml
- run: npm run build
- run: npx sentry-cli sourcemaps upload .next
- run: find .next -name '*.map' -delete    # nothing user-facing keeps a copy
```

Protects against: strangers reading your original source — comments, internal route names, feature
flags and the exact shape of every auth check.
Does **not** protect against: anything by itself. Minified JavaScript is still readable; source
maps only make it comfortable. Never treat obfuscation as a control.

<a id="exposed-files"></a>
## Keep sensitive paths off the public web

`.env`, `.git/`, SQL dumps and backups get published whenever they end up inside the deployed
directory. Check what is reachable right now:

```bash
for p in .env .env.local .env.production .git/config .git/HEAD backup.sql db.sqlite .DS_Store; do
  printf '%s  /%s\n' "$(curl -s -o /dev/null -w '%{http_code}' "https://your-site.com/$p")" "$p"
done
# anything that is not 404 or 403 is a finding
```

Then stop them shipping:

```
# .vercelignore  (also .dockerignore / .gcloudignore — same syntax)
.env*
!.env.example
.git
*.sql
*.bak
*.sqlite
```

```nginx
# self-hosted: refuse dotfiles at the edge, whatever the app does
location ~ /\.(env|git) { deny all; return 404; }
```

Where: an ignore file beside the code, plus the proxy rule if you run your own server. On Next.js
only `public/` is served statically — treat everything you put there as world-readable and keep
uploads, dumps and admin exports out of it.

Protects against: an attacker fetching your configuration directly, with no exploit involved.
Does **not** protect against: a file that was already fetched. Anything a deployed `.env` ever
contained must be rotated — see
[secrets-management.md](secrets-management.md#rotate-and-ignore).

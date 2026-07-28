# Supply chain / CI-CD checks

Applies to GitHub Actions, GitLab CI, package manifests, lockfiles, and git history. The build
pipeline and dependencies are an attack surface that vibecoders rarely think about.

## GitHub Actions / CI workflows
- **`pull_request_target` + checkout of PR head + running its code.** Classic RCE / secret-theft
  from a forked PR; the untrusted PR runs with repo secrets. **P0/P1**. Guard:
  `ci-hardening.md#pull-request-target`.
- **Unpinned actions** — `uses: some/action@v3` or `@master` instead of a full commit SHA. A
  compromised tag runs in your pipeline. **P2**. Guard: pin to SHA.
- **Secrets echoed to logs** — `run: echo ${{ secrets.X }}`, or `set -x` around secret use.
  **P1/P2**.
- **`${{ github.event.* }}` interpolated into a `run:` shell** (issue title, branch name, PR
  body) → script injection. **P1**, a very common real bug. Guard: pass via `env:` and quote.
- **Long-lived cloud keys** as secrets instead of OIDC federation. **P2**.
- **Overly broad `GITHUB_TOKEN` permissions** (no `permissions:` block → write-all). **P2**.
- **`workflow_run` / self-hosted runners** exposed to fork PRs. **P1**.

## Dependencies
- **Known-vulnerable packages** — `npm/pnpm audit`, `pip-audit`, `osv-scanner`, `trivy`.
  Severity from the advisory, capped by reachability. Guard: `dependency-hygiene.md`.
- **Dependency confusion** — internal package names not scoped/reserved on the public registry.
  **P1/P2**.
- **Malicious/risky `postinstall`** scripts. **P2**.
- **Unpinned / floating ranges** on critical deps; missing lockfile. **P3**.
- **Typosquat-shaped names** in dependencies. **P2** (flag for human review).

## Git history & repo hygiene
- **Secrets in git history** even after deletion — `gitleaks`/`trufflehog` over full history.
  Any live key found is **P0/P1**. Guard: rotate, then purge history.
- **`.gitignore` missing** `.env`, key files, `*.pem`, service-account JSON. **P2**.
- **Committed build artifacts / `node_modules`** hiding vendored vulnerabilities. **P3**.

## Verify
Workflow and manifest issues are `confirmed` from the file. "Secret in history" is `confirmed`
by the tool match; whether it's still *valid* is `likely` unless verified — always advise
rotation regardless, since assume-compromised is the safe default.

# Guard: dependency hygiene

## Find and fix known vulnerabilities
```bash
npm audit --json        # or: pnpm audit --json / yarn npm audit
npm audit fix           # safe upgrades; review before --force (can break)
pip-audit               # Python
osv-scanner -r .        # multi-ecosystem, uses the OSV database
trivy fs .              # deps + IaC + secrets in one pass
```
Fix priority = advisory severity **capped by reachability**: a critical CVE in a package you only
use at build time is lower risk than a high in a request-path dependency.

## Pin and lock
- Commit the lockfile (`package-lock.json`/`pnpm-lock.yaml`/`poetry.lock`); install with
  `npm ci` (not `npm install`) in CI for reproducible builds.
- Avoid floating ranges (`"latest"`, `"*"`) on security-relevant deps.

## Reduce supply-chain risk
- Review new dependencies before adding (downloads, maintenance, `postinstall` scripts).
- Watch for **typosquats** (`react-dom` vs `reactdom`) and **dependency confusion** — scope
  internal packages (`@yourorg/...`) and reserve the name on the public registry.
- Consider `npm install --ignore-scripts` for CI where install-time scripts aren't needed.
- Turn on Dependabot/Renovate for automated, reviewable updates.

## Keep it current, safely
Small frequent upgrades beat big risky ones. Gate upgrades behind your test suite so a bumped
dependency can't silently break the app.

// DELIBERATELY INSECURE SAMPLE for testing ClaudeGuardIL.
// P2/P3: no security headers (no CSP, HSTS, X-Frame-Options, etc.), source maps left on in prod.
module.exports = {
  productionBrowserSourceMaps: true, // P3: ships source maps to production
  // no async headers() { ... } → no security headers at all
}

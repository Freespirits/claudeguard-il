# iOS checks

Applies to native (Swift/Obj-C), React Native, Flutter, Capacitor. Audit sources: `Info.plist`,
`*.entitlements`, Swift/Obj-C source, and build settings. OWASP Mobile Top 10 tags.

## App Transport Security (Info.plist)
- **`NSAllowsArbitraryLoads = true`** → disables ATS, allows plain HTTP everywhere. MITM. **P1**.
  Guard: remove it; use per-domain exceptions only if truly needed.
- **Broad ATS exceptions** (`NSExceptionAllowsInsecureHTTPLoads` on many domains). **P2**.

## URL schemes & universal links
- **Custom URL scheme handler** that performs sensitive actions from parameters without
  validation (any app can invoke `myapp://pay?...`). **P1**, M1.
- **Universal links / deep links** trusted without verifying the source or the `apple-app-site-
  association`. **P2**.

## Secrets & storage (M9/M2)
- **Hardcoded secrets** in source, `Info.plist`, or `.plist` bundles (extractable from the IPA).
  **P0/P1**. Client-side keys are effectively public.
- **Secrets in `UserDefaults`** (unencrypted) instead of Keychain. **P2**.
- **Keychain misuse** — wrong accessibility (`kSecAttrAccessibleAlways`), no biometric gate on
  sensitive items. **P2/P3**.
- **Sensitive data cached** in screenshots/snapshots, or printed to logs (`print`, `NSLog`).
  **P3**.

## Transport & runtime
- **No certificate pinning** for sensitive APIs. **P3**.
- **Pasteboard leakage** — copying tokens/secrets to the general pasteboard. **P3**.
- **Jailbreak-obvious insecure storage** (data readable outside the sandbox). **P2**.

## Build
- **Debug/dev entitlements** or test endpoints shipped in the release build. **P2/P3**.
- **Insecure third-party SDK config** (analytics/ads keys with excessive scope). **P3**.

## Verify
`Info.plist` / source signals are usually `confirmed`. Keychain-accessibility and pinning are
often `likely` from static reads — recommend on-device testing (owned device) to confirm.

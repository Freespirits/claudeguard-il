# Android checks

Applies to native (Kotlin/Java), React Native, Flutter, Capacitor/Cordova. Audit sources:
`AndroidManifest.xml`, `res/`, Gradle files, `strings.xml`, and any decompiled/APK output.
OWASP Mobile Top 10 tags (M1–M10) where useful.

## Manifest
- **`android:debuggable="true"`** in a release build → attacker can attach a debugger. **P1**.
- **`android:allowBackup="true"`** (default) → app data extractable via `adb backup`. **P2**.
- **`usesCleartextTraffic="true"`** or missing `networkSecurityConfig` → HTTP allowed, MITM.
  **P2/P1**. Guard: `network-security-config.md`.
- **Exported components.** `activity`/`service`/`receiver`/`provider` with
  `android:exported="true"` (or an intent-filter and no explicit `exported`) and no permission →
  other apps can invoke it. **P1/P2**, M1. Guard: set `exported="false"` or require a signature
  permission.
- **Exported `ContentProvider`** with `grantUriPermissions`/no permission → data theft or
  injection. **P1**.

## Secrets & storage (M9/M2)
- **Hardcoded secrets** in `strings.xml`, `BuildConfig`, Kotlin/Java constants, or `gradle.
  properties` shipped in the APK. API keys, signing info, backend creds. **P0/P1**. Note: any
  key compiled into the app is extractable — treat client-side keys as public.
- **Plaintext `SharedPreferences`** for tokens/PII (no `EncryptedSharedPreferences`). **P2**.
- **Sensitive data in external storage** / logs (`Log.d` with tokens). **P2/P3**.

## Network (M5)
- **No certificate pinning** for sensitive APIs. **P3** (defense-in-depth).
- **Trusting user-added CAs** via a permissive `network_security_config.xml`. **P2**.

## WebView & deep links (M1/M7)
- **`setJavaScriptEnabled(true)` + `addJavascriptInterface`** exposing native methods to web
  content (esp. remote/untrusted). **P1**.
- **`loadUrl` with untrusted input** / `file://` access enabled. **P1/P2**.
- **Deep-link / intent redirection** — an exported activity that forwards an intent from another
  app without validation. **P1**.

## Build / signing
- **App signed with debug key** / v1-only signing. **P2/P3**.
- **Insecure update mechanism** (APK fetched over HTTP, no integrity check). **P1**.

## Verify
Static XML/source signals are usually `confirmed`. For "no cert pinning" and runtime-only issues,
mark `likely` and note that dynamic testing (Tier 2, on a device you own) would confirm.

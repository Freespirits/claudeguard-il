# Guard: Android network security & manifest hardening

<a id="cleartext"></a>
## Disallow cleartext, opt into HTTPS-only

`res/xml/network_security_config.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="system" />   <!-- do NOT trust user-added CAs -->
    </trust-anchors>
  </base-config>
</network-security-config>
```

`AndroidManifest.xml`:
```xml
<application
    android:networkSecurityConfig="@xml/network_security_config"
    android:usesCleartextTraffic="false"
    android:allowBackup="false"
    android:debuggable="false">   <!-- ensure release build sets this false -->
```

Pointing `networkSecurityConfig` at a file is not by itself a fix — the file decides. If one legacy
host genuinely cannot serve HTTPS, scope cleartext to that host and leave everything else closed:

```xml
<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="false">legacy.example.com</domain>
  </domain-config>
</network-security-config>
```

<a id="user-cas"></a>
## Do not trust user-installed certificate authorities

`<certificates src="user" />` tells the app to trust any CA on the device's user store. That is
every intercepting proxy, every MDM profile, and every "install this certificate to continue" page —
and the traffic looks completely normal while it happens. Keep the user store to debug builds only,
where it is scoped by `<debug-overrides>` and never compiled into a release:

```xml
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="system" />
    </trust-anchors>
  </base-config>

  <!-- applies ONLY to a build with android:debuggable="true" -->
  <debug-overrides>
    <trust-anchors>
      <certificates src="user" />
    </trust-anchors>
  </debug-overrides>
</network-security-config>
```

<a id="debuggable"></a>
## Keep debuggable out of the release variant

`android:debuggable` should not appear in `src/main/AndroidManifest.xml` at all — Gradle sets it per
variant, and a value hardcoded in the manifest overrides the build type:

```kotlin
// app/build.gradle.kts
android {
  buildTypes {
    debug   { isDebuggable = true }
    release { isDebuggable = false; isMinifyEnabled = true }
  }
}
```

Debug-only manifest entries belong in `src/debug/AndroidManifest.xml`, which is merged into debug
builds and never into a release. That is where `usesCleartextTraffic="true"` for a Metro or Flutter
dev server belongs.

<a id="exported"></a>
## Lock down exported components
```xml
<!-- Only export what genuinely needs to be reachable by other apps -->
<activity android:name=".InternalActivity" android:exported="false" />

<!-- If it must be exported, require a signature-level permission -->
<permission android:name="com.example.permission.SIGNATURE"
            android:protectionLevel="signature" />
<service android:name=".SyncService"
         android:exported="true"
         android:permission="com.example.permission.SIGNATURE" />
```
The protection level is the whole control. `protectionLevel="normal"` — Android's default when the
attribute is omitted — is granted to every app at install with no prompt, so a component "guarded"
by one is exactly as reachable as an unguarded one.

**The launcher activity is the exception.** The activity carrying
`<action android:name="android.intent.action.MAIN" />` and
`<category android:name="android.intent.category.LAUNCHER" />` must be exported — that is how the
home screen starts your app. Setting `android:exported="false"` on it, or putting a permission in
front of it, makes the app unlaunchable. Leave it as it is.

**A component with an `<intent-filter>` and no `android:exported`** is exported by default on
targetSdk 30 and below. Android 12 (targetSdk 31) makes the missing attribute a build error for
exactly this reason. Declare it explicitly either way.

`ContentProvider`: `android:exported="false"` unless designed for sharing; if shared, enforce
read/write permissions and parameterize all queries.

<a id="app-links"></a>
## Deep links: verify the domain, or assume anyone can send you one

A custom scheme (`myapp://reset?token=…`) is claimable by **any** app on the device — two apps can
register the same scheme and the user picks, or the other app wins silently. Treat every value
arriving through one as untrusted input from a stranger.

Only App Links with a verified domain are exclusive to your app:

```xml
<activity android:name=".DeepLinkActivity" android:exported="true">
  <intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https" android:host="app.example.com" />
  </intent-filter>
</activity>
```

Then serve `https://app.example.com/.well-known/assetlinks.json` with your signing certificate's
SHA-256 fingerprint. Verify with
`adb shell pm get-app-links com.example.app` — the domain must read `verified`.

Rules for the handler itself, whichever scheme it is on:

```kotlin
val data = intent.data ?: return
// 1. Never forward an attacker-supplied URI into another component or a WebView.
// 2. Never let a link COMPLETE a security decision — a reset link should open the reset
//    screen and require the user to act, not attach a session by itself.
// 3. Validate host and path against an allowlist before reading any parameter.
if (data.host !in setOf("app.example.com")) return
```

<a id="pinning"></a>
## Certificate pinning (sensitive APIs)
OkHttp:
```kotlin
val pinner = CertificatePinner.Builder()
  .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
  .build()
val client = OkHttpClient.Builder().certificatePinner(pinner).build()
```

<a id="backup"></a>
## Scope the backup set

`android:allowBackup` defaults to `true`, so omitting it and writing it out are the same thing. What
matters is what ends up in the backup. Either turn it off, or exclude the files that hold tokens:

```xml
<application
    android:allowBackup="true"
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:fullBackupContent="@xml/backup_rules">
```

`res/xml/data_extraction_rules.xml` (Android 12+):
```xml
<data-extraction-rules>
  <cloud-backup>
    <exclude domain="sharedpref" path="auth.xml" />
    <exclude domain="database" path="tokens.db" />
  </cloud-backup>
  <device-transfer>
    <exclude domain="sharedpref" path="auth.xml" />
  </device-transfer>
</data-extraction-rules>
```

<a id="storage"></a>
## Storage
Use `EncryptedSharedPreferences` (Jetpack Security) for tokens/PII; never log secrets; keep
sensitive data out of external storage. Remember: any key compiled into the APK is extractable —
use a backend for anything that must stay secret.

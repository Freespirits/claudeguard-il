# Guard: Android network security & manifest hardening

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

## Lock down exported components
```xml
<!-- Only export what genuinely needs to be reachable by other apps -->
<activity android:name=".InternalActivity" android:exported="false" />

<!-- If it must be exported, require a signature-level permission -->
<service android:name=".SyncService"
         android:exported="true"
         android:permission="com.example.permission.SIGNATURE" />
```
`ContentProvider`: `android:exported="false"` unless designed for sharing; if shared, enforce
read/write permissions and parameterize all queries.

## Certificate pinning (sensitive APIs)
OkHttp:
```kotlin
val pinner = CertificatePinner.Builder()
  .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
  .build()
val client = OkHttpClient.Builder().certificatePinner(pinner).build()
```

## Storage
Use `EncryptedSharedPreferences` (Jetpack Security) for tokens/PII; never log secrets; keep
sensitive data out of external storage. Remember: any key compiled into the APK is extractable —
use a backend for anything that must stay secret.

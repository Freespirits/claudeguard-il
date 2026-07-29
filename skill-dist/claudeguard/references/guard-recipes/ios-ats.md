# Guard: iOS App Transport Security, URL schemes and storage

Every iOS finding used to point at `network-security-config.md`, whose content is entirely Android —
`res/xml/`, `AndroidManifest.xml`, OkHttp, `EncryptedSharedPreferences`. A non-expert who clicked it
from an ATS finding got Android XML as the fix for an iOS problem. This file is the iOS half.

<a id="arbitrary-loads"></a>
## Turn App Transport Security back on

ATS is on by default: every connection must be HTTPS with TLS 1.2 or better. Turning it off globally
is the one line to remove.

```xml
<!-- Info.plist — DELETE this whole block if you can. -->
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSAllowsArbitraryLoads</key><true/>
</dict>
```

If one legacy host genuinely cannot serve HTTPS, scope the exception to that host and leave the rest
of the internet closed:

```xml
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSExceptionDomains</key>
  <dict>
    <key>legacy.example.com</key>
    <dict>
      <key>NSExceptionAllowsInsecureHTTPLoads</key><true/>
      <key>NSIncludesSubdomains</key><false/>
    </dict>
  </dict>
</dict>
```

Check your own file with `plutil -p ios/Runner/Info.plist` (or `App/App/Info.plist`). If Xcode wrote
it in the binary format, `plutil -convert xml1 Info.plist` makes it readable — and reviewable in a
diff, which is worth doing regardless.

**One subtlety worth knowing.** From iOS 10 onward, `NSAllowsArbitraryLoads` is *ignored* whenever
`NSAllowsArbitraryLoadsInWebContent`, `NSAllowsArbitraryLoadsForMedia` or `NSAllowsLocalNetworking`
is also present — the narrower key governs. So a plist with both is not as open as it looks on any
device made in the last decade, but it is still worth cleaning up: the broad key is doing nothing
except making the file hard to reason about, and it *does* apply if the target still deploys to
iOS 9.

<a id="web-content"></a>
## Web views

`NSAllowsArbitraryLoadsInWebContent` lets a `WKWebView` load plaintext HTTP. Content fetched over
HTTP can be rewritten in transit and then runs inside your app's origin, next to whatever your
`WKScriptMessageHandler` exposes. Remove the key and serve the content over HTTPS.

If a web view must load remote content, keep the bridge narrow:

```swift
let config = WKWebViewConfiguration()
// Expose specific, typed messages — never a generic "call any native method" handler.
config.userContentController.add(self, name: "saveNote")
let web = WKWebView(frame: .zero, configuration: config)
web.load(URLRequest(url: URL(string: "https://app.example.com")!))
```

<a id="url-schemes"></a>
## Custom URL schemes and universal links

A custom scheme (`myapp://pay?...`) declared in `CFBundleURLTypes` can be registered by **any** other
app on the device. It is an unauthenticated entry point into your app, from a stranger.

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array><string>myapp</string></array>
  </dict>
</array>
```

Only Universal Links are exclusive to you, because they are proved by a file on your own domain:

1. Add the Associated Domains capability with `applinks:app.example.com`.
2. Serve `https://app.example.com/.well-known/apple-app-site-association` (JSON, no extension, no
   redirect) listing your team + bundle id and the paths you claim.

Rules for the handler, on either kind of link:

```swift
func application(_ app: UIApplication, open url: URL, options: ...) -> Bool {
  // 1. Validate scheme, host and path against an allowlist before reading a parameter.
  // 2. Never let a link COMPLETE a security decision — open the screen, require the user to act.
  // 3. Never forward the URL into a web view or another component unchecked.
  guard url.host == "pay" else { return false }
  ...
}
```

<a id="storage"></a>
## Keychain, not UserDefaults

`UserDefaults` is an unencrypted plist inside the app container: readable on a jailbroken device, in
an unencrypted backup, and by anything with file access. Tokens, refresh tokens and PII belong in
the Keychain, with an accessibility class that actually restricts them.

```swift
let query: [String: Any] = [
  kSecClass as String: kSecClassGenericPassword,
  kSecAttrAccount as String: "refreshToken",
  kSecValueData as String: token.data(using: .utf8)!,
  // NOT kSecAttrAccessibleAlways — that defeats the point.
  kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
]
SecItemAdd(query as CFDictionary, nil)
```

<a id="secrets"></a>
## Keys compiled into the app are published

Anything in `Info.plist`, a bundled `.plist`, or a Swift constant is extractable from the IPA with
`unzip` and `strings`. Obfuscation, string-splitting and a native module do not change that — they
change how long it takes. If a value must stay secret, it belongs on a server that holds it and
exposes only the operation the app needs.

<a id="pinning"></a>
## Certificate pinning (defence in depth)

Pinning is a hardening measure, not a baseline. Add it for the endpoints that carry credentials,
after ATS is on.

```swift
func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
  guard let trust = challenge.protectionSpace.serverTrust,
        let cert = SecTrustGetCertificateAtIndex(trust, 0),
        SecCertificateCopyData(cert) as Data == pinnedCertificateData
  else { return completionHandler(.cancelAuthenticationChallenge, nil) }
  completionHandler(.useCredential, URLCredential(trust: trust))
}
```

Pin a public key rather than a leaf certificate where you can, and ship a rollover pin — a pinned
app whose certificate rotated without a matching release simply stops working.

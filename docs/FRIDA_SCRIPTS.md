# Built-in Frida Scripts

Overview of all 17 built-in Frida scripts included with Mobilicustos. These scripts cover root/jailbreak detection bypass, SSL pinning bypass, Frida detection evasion, runtime monitoring, exploitation, and reconnaissance.

## Table of Contents

- [Bypass Scripts](#bypass-scripts)
  - [Root Detection Bypass (Android)](#root-detection-bypass-android)
    - [root_bypass_generic](#root_bypass_generic)
    - [root_bypass_rootbeer](#root_bypass_rootbeer)
    - [root_bypass_safetynet](#root_bypass_safetynet)
  - [SSL Pinning Bypass (Android)](#ssl-pinning-bypass-android)
    - [ssl_bypass_okhttp3](#ssl_bypass_okhttp3)
    - [ssl_bypass_trustmanager](#ssl_bypass_trustmanager)
    - [ssl_bypass_universal_android](#ssl_bypass_universal_android)
  - [SSL Pinning Bypass (iOS)](#ssl-pinning-bypass-ios)
    - [ssl_bypass_nsurlsession](#ssl_bypass_nsurlsession)
    - [ssl_bypass_alamofire](#ssl_bypass_alamofire)
  - [Jailbreak Detection Bypass (iOS)](#jailbreak-detection-bypass-ios)
    - [jailbreak_bypass_generic](#jailbreak_bypass_generic)
    - [jailbreak_bypass_urlscheme](#jailbreak_bypass_urlscheme)
  - [Frida Detection Bypass](#frida-detection-bypass)
    - [frida_bypass_generic](#frida_bypass_generic)
- [Monitoring Scripts](#monitoring-scripts)
  - [crypto_monitor](#crypto_monitor)
  - [network_monitor](#network_monitor)
  - [filesystem_monitor](#filesystem_monitor)
  - [clipboard_monitor](#clipboard_monitor)
- [Exploitation Scripts](#exploitation-scripts)
  - [intent_intercept](#intent_intercept)
- [Reconnaissance Scripts](#reconnaissance-scripts)
  - [app_recon](#app_recon)
- [Output Format](#output-format)
- [Adding Custom Scripts](#adding-custom-scripts)
- [Compatibility Notes](#compatibility-notes)

---

## Bypass Scripts

### Root Detection Bypass (Android)

#### root_bypass_generic

- **Platform:** Android
- **Category:** bypass/root
- **Target Libraries:** None (generic)
- **Description:** Generic Android root-detection bypass. Hooks `java.io.File.exists()` to hide su/magisk/busybox paths, `Runtime.exec()` to block `which su` and `id` commands, and `SystemProperties.get()` for `ro.debuggable`/`ro.secure`.
- **What it hooks:**
  1. **`java.io.File.exists()`** -- Returns `false` for 26 known root indicator paths including `/system/xbin/su`, `/sbin/su`, `/data/adb/magisk`, `/sbin/.magisk`, `/system/xbin/busybox`, `/system/xbin/daemonsu`, and paths ending in `/su` (excluding `sugar`/`surf` false positives).
  2. **`java.lang.Runtime.exec(String)` and `Runtime.exec(String[])`** -- Throws `IOException("Permission denied")` when the command contains `which su`, `su`, `id`, or `busybox`.
  3. **`android.os.SystemProperties.get(String)` and `get(String, String)`** -- Returns spoofed values: `ro.debuggable` -> `"0"`, `ro.secure` -> `"1"`, `ro.build.selinux` -> `"1"`, `ro.build.tags` -> `"release-keys"`.
  4. **`android.os.Build.TAGS`** -- Patches static field from `test-keys` to `"release-keys"`.
  5. **`android.app.ApplicationPackageManager.getPackageInfo(String, int)`** -- Throws `NameNotFoundException` for 11 root-related packages including `com.topjohnwu.magisk`, `eu.chainfire.supersu`, `de.robv.android.xposed.installer`, `com.saurik.substrate`, etc.
- **Usage:** Automatically used by the bypass orchestrator when root detection is detected during dynamic analysis.
- **Limitations:** May not catch custom root detection implementations that use native code or obfuscated class names. Does not address native (C/C++) file-existence checks outside the JVM.

---

#### root_bypass_rootbeer

- **Platform:** Android
- **Category:** bypass/root
- **Target Libraries:** `com.scottyab.rootbeer`
- **Description:** Bypass RootBeer library (`com.scottyab.rootbeer.RootBeer`) root detection by hooking all its detection methods to return `false`.
- **What it hooks:**
  1. **`RootBeer.isRooted()`** -> `false`
  2. **`RootBeer.isRootedWithoutBusyBoxCheck()`** -> `false`
  3. **`RootBeer.detectRootManagementApps()`** -> `false`
  4. **`RootBeer.detectPotentiallyDangerousApps()`** -> `false`
  5. **`RootBeer.detectTestKeys()`** -> `false`
  6. **`RootBeer.checkForBinary(String)`** -> `false`
  7. **`RootBeer.checkForDangerousProps()`** -> `false`
  8. **`RootBeer.checkForRWPaths()`** -> `false`
  9. **`RootBeer.detectRootCloakingApps()`** -> `false`
  10. **`RootBeer.checkSuExists()`** -> `false`
  11. **`RootBeer.checkForRootNative()`** -> `false`
  12. **`RootBeer.checkForMagiskBinary()`** -> `false`
  13. **`RootBeerNative.checkForRoot(Object[])`** -> `0`
- **Usage:** Automatically selected when the RootBeer library is detected in the target app. Falls back gracefully if the library is not present.
- **Limitations:** Only effective against the RootBeer library. If the app uses a custom root detection mechanism in addition to RootBeer, pair this with `root_bypass_generic`.

---

#### root_bypass_safetynet

- **Platform:** Android
- **Category:** bypass/root
- **Target Libraries:** `com.google.android.gms.safetynet`
- **Description:** Bypass Google SafetyNet/Play Integrity attestation by hooking the response parsing to modify `ctsProfileMatch` and `basicIntegrity` to `true`. Also hooks Build fields commonly checked by SafetyNet.
- **What it hooks:**
  1. **`android.os.Build.TAGS`** -> `"release-keys"`
  2. **`android.os.Build.FINGERPRINT`** -> replaces `test-keys` with `release-keys`
  3. **`android.os.Build.TYPE`** -> `"user"`
  4. **`SafetyNetApi$AttestationResponse.getJwsResult()`** -- Intercepts and logs the JWS result (no modification; actual bypass at JSON parse level).
  5. **`org.json.JSONObject.getBoolean(String)`** -- Returns `true` when key is `ctsProfileMatch` or `basicIntegrity`.
  6. **`org.json.JSONObject.optBoolean(String)` and `optBoolean(String, boolean)`** -- Returns `true` for the same keys.
  7. **`DroidGuardHelper.init()`** -- Intercepts DroidGuard initialization (if present).
  8. **`android.os.SystemProperties.get(String, String)`** -- Returns: `ro.boot.verifiedbootstate` -> `"green"`, `ro.boot.flash.locked` -> `"1"`, `ro.boot.vbmeta.device_state` -> `"locked"`.
- **Usage:** Used when SafetyNet/Play Integrity attestation causes app failures on rooted devices.
- **Limitations:** Modern Play Integrity (hardware-backed attestation) cannot be bypassed purely via Frida hooks. This only works against software-level SafetyNet checks.

---

### SSL Pinning Bypass (Android)

#### ssl_bypass_okhttp3

- **Platform:** Android
- **Category:** bypass/ssl_pinning
- **Target Libraries:** `okhttp3`
- **Description:** Bypass OkHttp3 certificate pinning by hooking `okhttp3.CertificatePinner.check()` and `check$okhttp()` to no-op.
- **What it hooks:**
  1. **`okhttp3.CertificatePinner.check(String, List)`** -- Returns void (no-op), skipping pin validation.
  2. **`okhttp3.CertificatePinner.check$okhttp(String, Function)`** -- Kotlin variant, returns void (no-op).
  3. **`com.squareup.okhttp.OkHttpClient.setCertificatePinner(CertificatePinner)`** -- Legacy OkHttp v2 bypass, returns `this` without setting pinner.
- **Usage:** Use when the target app uses OkHttp3 (or OkHttp v2) for network communication. This is one of the most common HTTP libraries on Android.
- **Limitations:** Only bypasses OkHttp-specific pinning. If the app also uses platform-level pinning or a custom TrustManager, combine with `ssl_bypass_trustmanager` or `ssl_bypass_universal_android`.

---

#### ssl_bypass_trustmanager

- **Platform:** Android
- **Category:** bypass/ssl_pinning
- **Target Libraries:** None (generic Android SSL)
- **Description:** Bypass Android SSL/TLS certificate validation by hooking `X509TrustManager.checkServerTrusted()`, `checkClientTrusted()` to no-op, and `SSLContext.init()` to use a permissive TrustManager.
- **What it hooks:**
  1. **`javax.net.ssl.SSLContext.init(KeyManager[], TrustManager[], SecureRandom)`** -- Replaces the TrustManager array with a custom `com.mobilicustos.PermissiveTrustManager` that accepts all certificates.
  2. **Custom registered class `com.mobilicustos.PermissiveTrustManager`** -- Implements `X509TrustManager` with no-op `checkClientTrusted()` and `checkServerTrusted()`, and returns empty `getAcceptedIssuers()`.
  3. **`javax.net.ssl.TrustManagerFactory.getTrustManagers()`** -- Intercepts and logs (pass-through).
  4. **`com.android.org.conscrypt.TrustManagerImpl.verifyChain()`** -- Returns the untrusted chain as-is, bypassing Conscrypt platform verification.
- **Usage:** Use as a general-purpose SSL bypass when the specific pinning library is unknown.
- **Limitations:** Does not handle OkHttp-specific `CertificatePinner` checks. Use alongside `ssl_bypass_okhttp3` for comprehensive coverage.

---

#### ssl_bypass_universal_android

- **Platform:** Android
- **Category:** bypass/ssl_pinning
- **Target Libraries:** None (universal)
- **Description:** Universal Android SSL pinning bypass combining: OkHttp3 CertificatePinner, X509TrustManager, SSLContext, `HttpsURLConnection.setDefaultHostnameVerifier`, and `WebViewClient.onReceivedSslError`.
- **What it hooks:**
  1. **`javax.net.ssl.SSLContext.init()`** -- Replaces TrustManager with `com.mobilicustos.UniversalPermissiveTM`.
  2. **`okhttp3.CertificatePinner.check(String, List)`** -- No-op bypass.
  3. **`okhttp3.CertificatePinner.check$okhttp()`** -- Kotlin variant no-op bypass.
  4. **`javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier()`** -- Replaces with `com.mobilicustos.UniversalPermissiveHV` that always returns `true`.
  5. **`javax.net.ssl.HttpsURLConnection.setHostnameVerifier()`** -- Same permissive replacement.
  6. **`javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory()`** -- Intercepted and logged.
  7. **`android.webkit.WebViewClient.onReceivedSslError()`** -- Calls `handler.proceed()` to accept SSL errors in WebViews.
  8. **`com.android.org.conscrypt.TrustManagerImpl.verifyChain()`** -- Returns untrusted chain directly.
  9. **`org.apache.http.conn.ssl.AbstractVerifier.verify(String, String[], String[], boolean)`** -- No-op bypass for legacy Apache HttpClient.
- **Usage:** Recommended as the first-choice Android SSL bypass script. Covers the widest range of SSL implementations in a single script.
- **Limitations:** Does not cover iOS. For Flutter apps, Java-level hooks will not capture Flutter/Dart network traffic (Flutter uses its own BoringSSL via native code).

---

### SSL Pinning Bypass (iOS)

#### ssl_bypass_nsurlsession

- **Platform:** iOS
- **Category:** bypass/ssl_pinning
- **Target Libraries:** None (generic iOS)
- **Description:** Bypass iOS SSL pinning via NSURLSession by hooking `URLSession:didReceiveChallenge:completionHandler:` to accept all server certificates. Handles `NSURLAuthenticationMethodServerTrust`.
- **What it hooks:**
  1. **`-[* URLSession:didReceiveChallenge:completionHandler:]`** -- Uses `ApiResolver('objc')` to find all classes implementing this delegate method. For `NSURLAuthenticationMethodServerTrust` challenges, creates a `NSURLCredential` with `credentialForTrust:` and invokes the completionHandler with `NSURLSessionAuthChallengeUseCredential` (disposition 0).
  2. **`SecTrustEvaluate` (Security framework)** -- Replaces return value with `errSecSuccess` (0).
  3. **`SecTrustEvaluateWithError` (Security framework)** -- Replaces return value with `1` (trusted).
  4. **`-[NSURLSession dataTaskWithRequest:completionHandler:]`** -- Logs outgoing request URLs for visibility.
- **Usage:** Use as the primary iOS SSL bypass. Works with any app using NSURLSession (which is the foundation for most iOS networking).
- **Limitations:** Does not handle third-party libraries that implement their own trust evaluation (e.g., Alamofire with custom evaluators). Combine with `ssl_bypass_alamofire` for full coverage.

---

#### ssl_bypass_alamofire

- **Platform:** iOS
- **Category:** bypass/ssl_pinning
- **Target Libraries:** `Alamofire`
- **Description:** Bypass Alamofire SSL pinning by hooking `ServerTrustEvaluating` evaluate methods and the `ServerTrustManager` to accept all certificates.
- **What it hooks:**
  1. **`-[*ServerTrustManager evaluate*]`** -- Returns `nil` (no error) to bypass trust evaluation.
  2. **`-[*DefaultTrustEvaluator evaluate*]`** -- Bypassed.
  3. **`-[*RevocationTrustEvaluator evaluate*]`** -- Bypassed.
  4. **`-[*PinnedCertificatesTrustEvaluator evaluate*]`** -- Bypassed (covers Alamofire 5.x certificate pinning).
  5. **`-[*PublicKeysTrustEvaluator evaluate*]`** -- Bypassed (covers Alamofire 5.x public key pinning).
  6. **`SecTrustEvaluateWithError` (Security framework)** -- Returns `1` (trusted) for completeness.
- **Usage:** Use when the target iOS app uses Alamofire for networking. Often paired with `ssl_bypass_nsurlsession` for full coverage.
- **Limitations:** Targets Alamofire 5.x patterns. Older Alamofire versions (3.x/4.x) use different class names and may not be caught.

---

### Jailbreak Detection Bypass (iOS)

#### jailbreak_bypass_generic

- **Platform:** iOS
- **Category:** bypass/jailbreak
- **Target Libraries:** None (generic)
- **Description:** Generic iOS jailbreak detection bypass. Hooks `NSFileManager fileExistsAtPath:` for Cydia, substrate, bash, sshd, apt paths. Hooks `UIApplication canOpenURL:` for `cydia://`. Hides `fork`/`popen`.
- **What it hooks:**
  1. **`-[NSFileManager fileExistsAtPath:]`** -- Returns `NO` (0) for 35 jailbreak indicator paths including `/Applications/Cydia.app`, `/Applications/Sileo.app`, `/Library/MobileSubstrate/MobileSubstrate.dylib`, `/bin/bash`, `/usr/sbin/sshd`, `/usr/sbin/frida-server`, `/usr/bin/cycript`, `/etc/apt`, `/private/var/lib/cydia`, and more.
  2. **`-[NSFileManager fileExistsAtPath:isDirectory:]`** -- Same path filtering as above.
  3. **`-[UIApplication canOpenURL:]`** -- Returns `NO` for `cydia://`, `sileo://`, `zbra://`, and `filza://` URL schemes.
  4. **`fork()` (libSystem.B.dylib)** -- Returns `-1` (pretend failure) to prevent fork-based jailbreak detection.
  5. **`popen()` (libSystem.B.dylib)** -- Returns `NULL` when the command contains `which` or `su`.
  6. **`access()` (libSystem.B.dylib)** -- Returns `-1` for all jailbreak indicator paths.
  7. **`stat()` (libSystem.B.dylib)** -- Returns `-1` for all jailbreak indicator paths.
- **Usage:** Recommended as the first-choice iOS jailbreak bypass. Covers file existence checks, URL scheme checks, and native syscall-based detection.
- **Limitations:** Does not cover sandbox escape checks, dylib injection detection, or advanced environment integrity checks. Some apps may use `dlopen`/`dlsym` to detect Substrate/Frida dylibs.

---

#### jailbreak_bypass_urlscheme

- **Platform:** iOS
- **Category:** bypass/jailbreak
- **Target Libraries:** None (generic)
- **Description:** Bypass jailbreak detection via URL scheme checks. Hooks `UIApplication canOpenURL:` for `cydia://`, `sileo://`, `zbra://`, `filza://`, and other jailbreak-related URL schemes.
- **What it hooks:**
  1. **`-[UIApplication canOpenURL:]`** -- Returns `NO` (0) for 7 jailbreak URL schemes: `cydia://`, `sileo://`, `zbra://`, `filza://`, `undecimus://`, `activator://`, `ssh://`.
  2. **`-[UIApplication openURL:]`** (deprecated) -- Returns `NO` for the same jailbreak URL schemes.
  3. **`-[UIApplication openURL:options:completionHandler:]`** (iOS 10+) -- Blocks requests to jailbreak URL schemes.
  4. **`-[LSApplicationWorkspace applicationIsInstalled:]`** -- Returns `NO` for jailbreak app bundle IDs: `com.saurik.Cydia`, `org.coolstar.SileoStore`, `xyz.willy.Zebra`, `com.tigisoftware.Filza`.
- **Usage:** Use as a lightweight, targeted bypass when the app only uses URL scheme checks for jailbreak detection. For comprehensive coverage, use `jailbreak_bypass_generic` instead.
- **Limitations:** Only covers URL scheme and app-installation-based detection. Does not handle file existence checks, native syscall detection, or process enumeration.

---

### Frida Detection Bypass

#### frida_bypass_generic

- **Platform:** Android, iOS
- **Category:** bypass/frida
- **Target Libraries:** None (generic)
- **Description:** Hide Frida presence from detection. Hides port 27042 listener, hides frida thread names (`gum-js-loop`, `gmain`, `linjector`, etc.), hooks `open()` to filter frida strings from `/proc/self/maps`, and hides frida named pipes.
- **What it hooks:**
  1. **`open()` (libc.so, Android)** -- Tracks file descriptors for `/proc/self/maps` and `/proc/<pid>/maps`.
  2. **`read()` (libc.so, Android)** -- Filters lines containing `frida`, `gadget`, or `linjector` from `/proc/self/maps` reads.
  3. **`connect()` (cross-platform)** -- Returns `-1` (ECONNREFUSED) when the target port is 27042 (default Frida server port) to prevent port-scan-based detection.
  4. **`openat()` (cross-platform)** -- Returns `-1` when the path contains `frida`, `linjector`, or `gadget` to hide Frida named pipes and temp files.
  5. **`java.io.BufferedReader.readLine()` (Android)** -- Skips lines containing `frida` or `27042` when apps read process information.
- **Usage:** Should be injected before or alongside other scripts when the target app performs Frida detection. This is critical for apps with anti-tampering measures.
- **Limitations:** Does not hide Frida memory artifacts that advanced detection (e.g., inline hook pattern scanning) might find. Thread name hiding is not implemented in the current version. Some apps scan `/proc/self/maps` using direct syscalls that may not be caught by the libc hooks.

---

## Monitoring Scripts

### crypto_monitor

- **Platform:** Android
- **Category:** monitor
- **Description:** Monitor cryptographic operations by hooking `javax.crypto.Cipher` init/doFinal, `MessageDigest` update/digest, and `Mac` init/doFinal. Logs algorithm, key size, IV, and data snippets.
- **What it hooks:**
  1. **`javax.crypto.Cipher.init(int, Key)`** -- Logs operation mode (ENCRYPT/DECRYPT), algorithm, key algorithm, key size in bits, and key hex (first 32 bytes).
  2. **`javax.crypto.Cipher.init(int, Key, AlgorithmParameterSpec)`** -- Same as above, plus extracts and logs the IV (initialization vector) from `IvParameterSpec`.
  3. **`javax.crypto.Cipher.doFinal(byte[])`** -- Logs algorithm, input hex, and output hex (first 32 bytes each).
  4. **`javax.crypto.Cipher.doFinal()`** (no-arg variant) -- Logs algorithm and output hex.
  5. **`java.security.MessageDigest.update(byte[])`** -- Logs hash algorithm and input hex.
  6. **`java.security.MessageDigest.digest()`** -- Logs algorithm and hash output hex.
  7. **`java.security.MessageDigest.digest(byte[])`** -- Logs algorithm, input hex, and hash output hex.
  8. **`javax.crypto.Mac.init(Key)`** -- Logs HMAC algorithm, key algorithm, and key hex.
  9. **`javax.crypto.Mac.doFinal(byte[])`** -- Logs algorithm, input hex, and HMAC output hex.
  10. **`javax.crypto.Mac.doFinal()`** (no-arg variant) -- Logs algorithm and HMAC output hex.
  11. **`java.security.Signature.sign()`** -- Logs algorithm and signature output hex.
  12. **`javax.crypto.spec.SecretKeySpec(byte[], String)`** -- Logs key material hex and key size at construction time.
- **Logged data:** Algorithm name, key size (bits), key hex (truncated at 32 bytes), IV hex, input/output hex (truncated at 32 bytes with total byte count).
- **Usage:** Essential for identifying insecure cryptographic practices such as weak algorithms (DES, MD5), hardcoded keys, ECB mode, short key lengths, or missing IVs.
- **Limitations:** Only monitors Java-level crypto APIs. Native crypto (OpenSSL, BoringSSL, libsodium) and Flutter Dart crypto are not captured.

---

### network_monitor

- **Platform:** Android
- **Category:** monitor
- **Description:** Monitor network operations by hooking `URL.openConnection()`, `OkHttpClient.newCall()`, `HttpURLConnection` connect/getOutputStream. Logs URLs, HTTP methods, request headers, and response codes.
- **What it hooks:**
  1. **`java.net.URL.openConnection()`** -- Logs full URL, protocol, host, and path.
  2. **`java.net.URL.openConnection(Proxy)`** -- Logs URL and proxy details.
  3. **`java.net.HttpURLConnection.setRequestMethod(String)`** -- Logs HTTP method and URL.
  4. **`java.net.HttpURLConnection.connect()`** -- Logs URL and HTTP method at connection time.
  5. **`java.net.HttpURLConnection.getResponseCode()`** -- Logs URL and HTTP status code.
  6. **`javax.net.ssl.HttpsURLConnection.connect()`** -- Logs HTTPS connections with URL and method.
  7. **`okhttp3.OkHttpClient.newCall(Request)`** -- Logs URL, HTTP method, and up to 20 request headers.
  8. **`okhttp3.RealCall.execute()`** -- Logs response URL, status code, status message, and up to 10 response headers.
  9. **`android.webkit.WebView.loadUrl(String)` and `loadUrl(String, Map)`** -- Logs WebView URL loading.
  10. **`java.net.Socket(String, int)`** -- Logs raw TCP socket connections with host and port.
- **Usage:** Use to observe all network traffic from an Android app, identify API endpoints, detect cleartext HTTP usage, and discover hidden or undocumented API calls.
- **Limitations:** Only monitors Java-level networking. Flutter apps use Dart/native networking (BoringSSL), which is not captured by these hooks. For Flutter apps, use network-level interception (mitmproxy/Burp) instead.

---

### filesystem_monitor

- **Platform:** Android
- **Category:** monitor
- **Description:** Monitor filesystem operations by hooking `File` constructors, `FileInputStream`/`FileOutputStream`, and `SharedPreferences` getString/putString/edit. Logs file paths and operations.
- **What it hooks:**
  1. **`java.io.File(String)`** -- Logs file path construction.
  2. **`java.io.File(String, String)`** -- Logs parent/child path construction.
  3. **`java.io.File(File, String)`** -- Logs parent file + child path construction.
  4. **`java.io.FileInputStream(File)` and `FileInputStream(String)`** -- Logs file read operations.
  5. **`java.io.FileOutputStream(File)`, `FileOutputStream(String)`, and `FileOutputStream(File, boolean)`** -- Logs file write operations (including append mode).
  6. **`android.app.SharedPreferencesImpl.getString(String, String)`** -- Logs key and value (truncated at 100 chars).
  7. **`android.app.SharedPreferencesImpl.getInt(String, int)`** -- Logs key and integer value.
  8. **`android.app.SharedPreferencesImpl.getBoolean(String, boolean)`** -- Logs key and boolean value.
  9. **`android.app.SharedPreferencesImpl$EditorImpl.putString(String, String)`** -- Logs key and value being written (truncated at 100 chars).
  10. **`android.app.SharedPreferencesImpl$EditorImpl.putInt(String, int)`** -- Logs key and integer value.
  11. **`android.app.SharedPreferencesImpl$EditorImpl.putBoolean(String, boolean)`** -- Logs key and boolean value.
  12. **`android.app.SharedPreferencesImpl$EditorImpl.remove(String)`** -- Logs key removal.
  13. **`android.app.SharedPreferencesImpl$EditorImpl.commit()`** -- Logs commit operations.
  14. **`android.content.ContentResolver.query(Uri, ...)`** -- Logs content provider query URIs.
  15. **`android.content.ContentResolver.insert(Uri, ContentValues)`** -- Logs content provider insert URIs.
  16. **`android.database.sqlite.SQLiteDatabase.openDatabase(String, ...)`** -- Logs database open operations.
  17. **`android.database.sqlite.SQLiteDatabase.rawQuery(String, String[])`** -- Logs SQL queries (truncated at 200 chars).
  18. **`android.database.sqlite.SQLiteDatabase.execSQL(String)`** -- Logs SQL execution (truncated at 200 chars).
- **Usage:** Use to identify insecure data storage practices such as sensitive data in SharedPreferences, world-readable files, cleartext credentials on disk, or unencrypted SQLite databases.
- **Limitations:** Very verbose -- may produce significant output. Does not capture native-level file I/O or direct `open()`/`write()` syscalls.

---

### clipboard_monitor

- **Platform:** Android
- **Category:** monitor
- **Description:** Monitor clipboard operations by hooking `ClipboardManager` `setPrimaryClip`/`getPrimaryClip`. Logs clipboard data content including text, URIs, and intents.
- **What it hooks:**
  1. **`android.content.ClipboardManager.setPrimaryClip(ClipData)`** -- Logs label, item count, text content (truncated at 500 chars), URIs, and intents for each clip item. Also logs a stack trace (6 frames) to identify the caller.
  2. **`android.content.ClipboardManager.getPrimaryClip()`** -- Logs item count and text content for each clip item. Also logs a caller stack trace.
  3. **`android.content.ClipboardManager.getPrimaryClipDescription()`** -- Logs label and MIME type count.
  4. **`android.content.ClipboardManager.hasPrimaryClip()`** -- Logs the boolean result.
  5. **`android.content.ClipData.newPlainText(CharSequence, CharSequence)`** -- Logs static plain-text clip creation with label and text (truncated at 200 chars).
- **Usage:** Use to detect apps that copy sensitive data (passwords, tokens, PII) to the clipboard, which is accessible to all apps on older Android versions.
- **Limitations:** Only monitors the Java ClipboardManager API. Does not detect native-level clipboard access.

---

## Exploitation Scripts

### intent_intercept

- **Platform:** Android
- **Category:** exploit
- **Description:** Intercept and log Android Intent operations: `startActivity()`, `sendBroadcast()`, `startService()`. Logs intent action, data URI, extras bundle, component name, and flags.
- **What it hooks:**
  1. **`android.app.Activity.startActivity(Intent)`** -- Logs full intent dump.
  2. **`android.app.Activity.startActivity(Intent, Bundle)`** -- Logs intent dump with options bundle.
  3. **`android.app.Activity.startActivityForResult(Intent, int)`** -- Logs intent dump with request code.
  4. **`android.content.ContextWrapper.sendBroadcast(Intent)`** -- Logs broadcast intent dump.
  5. **`android.content.ContextWrapper.sendBroadcast(Intent, String)`** -- Logs broadcast with receiver permission.
  6. **`android.content.ContextWrapper.startService(Intent)`** -- Logs service start intent dump.
  7. **`android.content.ContextWrapper.sendOrderedBroadcast(Intent, String)`** -- Logs ordered broadcast intent dump.
  8. **`android.content.ContextWrapper.startForegroundService(Intent)`** (API 26+) -- Logs foreground service intent dump.
  9. **`android.app.PendingIntent.getActivity(Context, int, Intent, int)`** -- Logs PendingIntent creation for activities.
  10. **`android.app.PendingIntent.getBroadcast(Context, int, Intent, int)`** -- Logs PendingIntent creation for broadcasts.
  11. **`android.app.PendingIntent.getService(Context, int, Intent, int)`** -- Logs PendingIntent creation for services.
- **Logged data per intent:** Action, data URI, MIME type, component name, categories, flags (hex), and all extras (key-value pairs, values truncated at 200 chars).
- **Usage:** Use to discover exported components, implicit intents that could be intercepted, sensitive data passed via intents, and IPC attack surface.
- **Limitations:** Does not intercept intents sent via `ContentResolver` or AIDL-based binder calls. Cannot modify intents in-flight (monitoring only).

---

## Reconnaissance Scripts

### app_recon

- **Platform:** Android
- **Category:** recon
- **Description:** Enumerate loaded classes and app components. Find classes matching patterns (Activity, Service, Receiver, Provider, WebView). List registered content providers. Get app info and permissions.
- **What it gathers:**
  1. **Application Info** -- Package name, version name and code, target SDK, min SDK, source directory, data directory, native library directory, UID, debuggable flag, backup flag.
  2. **Requested Permissions** -- Full list of all permissions declared in the manifest.
  3. **Activities** -- All declared activities with their exported status (`[EXPORTED]` marker).
  4. **Services** -- All declared services with exported status.
  5. **Broadcast Receivers** -- All declared receivers with exported status.
  6. **Content Providers** -- All declared providers with authority and exported status.
  7. **Loaded Classes (pattern matching)** -- Scans all loaded classes within the app's package namespace matching: `Activity$`, `Service$`, `Receiver$`, `Provider$`, `WebView`, `Cipher|Crypto|Encrypt|Decrypt|AES|RSA|DES`, `Http|Socket|Volley|Retrofit|OkHttp`, `SQLite|Database|Realm|Room`.
  8. **Native Libraries** -- Enumerates all loaded native modules under `/data/` with module name, path, base address, and size.
- **Usage:** Run at the start of an assessment to map the app's attack surface: exported components, dangerous permissions, crypto class usage, network libraries, and database implementations.
- **Limitations:** Class enumeration only finds already-loaded classes. Dynamically loaded classes (via DexClassLoader or reflection) will not appear until they are loaded at runtime.

---

## Output Format

All scripts use standardized console output markers for consistent parsing:

| Marker | Meaning | Example |
|--------|---------|---------|
| `[+]` | Success / bypass applied | `[+] root_bypass_generic: File.exists("/system/xbin/su") -> false` |
| `[-]` | Error / hook failure | `[-] root_bypass_rootbeer: RootBeer class not found - library not present` |
| `[*]` | Informational / monitoring data | `[*] crypto_monitor: Cipher.init(ENCRYPT) Algorithm: AES/CBC/PKCS5Padding` |

Each log line is prefixed with the script's TAG (matching the `script_name`) for easy filtering when multiple scripts are active simultaneously.

---

## Adding Custom Scripts

Users can add their own Frida scripts to Mobilicustos via the Frida API in three ways:

### 1. Direct creation via API

Send a `POST` request to `/api/frida/scripts` with a JSON body:

```json
{
  "script_name": "my_custom_hook",
  "category": "custom",
  "subcategory": "example",
  "description": "Description of what the script does",
  "platforms": ["android"],
  "script_content": "Java.perform(function() { ... });"
}
```

### 2. File upload

Send a `POST` request to `/api/frida/scripts/import` as multipart form data with a `.js` file:

- `file`: The JavaScript file (max 5MB)
- `script_name`: Optional name (defaults to filename without extension)
- `category`: Script category (defaults to `custom`)
- `subcategory`: Optional subcategory
- `description`: Optional description
- `platforms`: Comma-separated platforms (defaults to `android,ios`)

### 3. URL import

Send a `POST` request to `/api/frida/scripts/import` with form data:

- `url`: URL to fetch the script from. Supports:
  - Direct URLs to raw `.js` files
  - GitHub raw URLs (e.g., `https://raw.githubusercontent.com/user/repo/main/script.js`)
  - Frida CodeShare projects using the `codeshare:project-name` prefix
- `script_name`, `category`, `subcategory`, `description`, `platforms`: Same as file upload

### Script validation

Imported scripts are validated to ensure they contain recognized Frida API patterns such as `Java.perform`, `Interceptor.attach`, `ObjC.classes`, `Module.find`, `Memory.read`, `NativeFunction`, or standard JavaScript constructs. Scripts that do not match any known Frida patterns will be rejected.

### Managing custom scripts

- **List scripts:** `GET /api/frida/scripts` with optional filters (`category`, `subcategory`, `platform`, `search`)
- **View script:** `GET /api/frida/scripts/{script_id}`
- **Update script:** `PUT /api/frida/scripts/{script_id}` (custom scripts only; built-in scripts cannot be modified)
- **Delete script:** `DELETE /api/frida/scripts/{script_id}` (custom scripts only; built-in scripts cannot be deleted)
- **Inject script:** `POST /api/frida/inject` with `device_id`, `app_id`, and either `script_id` or raw `script_content`

---

## Compatibility Notes

- **Android scripts** target API 21+ (Android 5.0 Lollipop and above) and use `Java.perform()` for JVM hooking.
- **iOS scripts** require a jailbroken device with Frida server installed and use `ObjC.classes` / `Interceptor.attach` for Objective-C runtime hooking.
- **Flutter apps** use Dart and native networking (BoringSSL). Java-level Frida hooks **will not capture** Flutter network traffic or crypto operations. Use network-level interception (mitmproxy, Burp Suite) for Flutter app analysis.
- **Frida server version** must match the client version at the major level (e.g., 16.x server with 16.x client). Mismatched versions will cause spawn/attach failures. The `enumerate_processes()` call may work even with mismatched versions, but `spawn()` and `attach()` will not.
- **Frida server 17.x** has known crash issues (SIGABRT) on certain devices (e.g., Pixel 3 XL / Android 11). Pin to `frida>=16.5.9,<17.0.0` if you encounter stability issues.
- The **frida_bypass_generic** script is cross-platform (Android + iOS). All other bypass scripts are platform-specific.
- **Docker environments** cannot use `get_usb_device()` for Frida connections. Use `add_remote_device()` with TCP tunneling (`adb forward tcp:27042 tcp:27042`) instead.

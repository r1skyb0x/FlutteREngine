# FlutteREngine — Flutter SSL Pinning Bypass Toolkit

A two-pronged toolkit for disabling SSL certificate pinning in Flutter Android
apps during security research and penetration testing.

| Tool | Method | Root required? |
|------|--------|----------------|
| `patch_flutter.py` | Static binary patch (libflutter.so) | No |
| `frida_ssl_bypass.js` | Runtime hook via Frida | Yes (Frida server) |

---

## How SSL pinning works in Flutter

Flutter embeds **BoringSSL** inside `libflutter.so`.  The function
`ssl_verify_peer_cert` (in `ssl/ssl_x509.cc`) validates the server's
certificate chain and returns an `ssl_verify_result_t` enum:

```
ssl_verify_ok      = 0   ← what we want it to always return
ssl_verify_invalid = 1
ssl_verify_retry   = 2
```

Both tools force this function to return `0` unconditionally, making the
Flutter engine accept any certificate — including self-signed ones used by
intercepting proxies (Burp Suite, mitmproxy, Charles).

---

## Engine Version Database (`enginehash.csv`)

The CSV maps Flutter release versions to their engine git commit and the
MD5 "snapshot hash" that is embedded as a literal string inside every
`libflutter.so`.  The patcher uses this database to identify which Flutter
version is running inside a target APK.

| Column | Description |
|--------|-------------|
| `version` | Flutter SDK version string |
| `Engine_commit` | Full git SHA of the Flutter engine commit |
| `Snapshot_Hash` | MD5 string embedded in `libflutter.so` |

---

## Static Patcher — `patch_flutter.py`

### Requirements

- Python 3.9+  (no third-party packages needed)
- `zipalign`, `apksigner` / `jarsigner`, `keytool` — optional, from Android SDK;
  used for alignment and re-signing.  Without them the patched APK is saved
  unsigned and you must sign it separately.

### Installation

```bash
git clone https://github.com/r1skyb0x/FlutteREngine
cd FlutteREngine
python patch_flutter.py --help
```

### Usage

```bash
# Patch an APK  (output: myapp_patched.apk)
python patch_flutter.py myapp.apk

# Specify output file
python patch_flutter.py myapp.apk -o ssl_free.apk

# Identify Flutter version without patching
python patch_flutter.py --info myapp.apk

# Override the patch offset when auto-detection fails
python patch_flutter.py myapp.apk --offset 0x1a2b3c

# List all known Flutter engine versions in the database
python patch_flutter.py --list-versions
```

### How it works

1. **Extract** — unzips the APK into a temp directory.
2. **Identify** — scans `libflutter.so` for embedded snapshot hashes and
   looks them up in `enginehash.csv` to print the Flutter version.
3. **Find** `ssl_verify_peer_cert` — searches the binary for architecture-
   specific BoringSSL error-constant byte patterns and walks back to the
   nearest function prologue:

   | Arch | Search pattern | Patch |
   |------|----------------|-------|
   | arm64-v8a | `MOVZ W*, #0x86` (`?? 10 80 52`) | `MOVZ X0, #0 ; RET` (8 B) |
   | armeabi-v7a | Thumb-2 MOVW / packed error const | `MOVS R0, #0 ; BX LR` (4 B) |
   | x86_64 / x86 | BoringSSL error constant `0x14000086` | `XOR EAX,EAX ; RET` (3 B) |

4. **Repack** — rebuilds the APK preserving native-library STORE compression.
5. **Sign** — uses `apksigner` (preferred) or `jarsigner` with a freshly
   generated debug keystore.

### Install the patched APK

```bash
adb install -r myapp_patched.apk
```

> **Note:** The patched APK is signed with a throwaway debug key.  If the app
> uses signature-based root detection you will need to address that separately.

---

## Runtime Hook — `frida_ssl_bypass.js`

### Requirements

- [Frida](https://frida.re) 16+ installed on your host machine
- `frida-server` running on the target Android device (rooted)

### Usage

```bash
# Spawn and patch from the start
frida -U -f com.example.app -l frida_ssl_bypass.js --no-pause

# Attach to a running process
frida -U --attach-pid 12345 -l frida_ssl_bypass.js

# iOS
frida -U -f com.example.app -l frida_ssl_bypass.js --no-pause
```

### Strategies (tried in order)

| # | Strategy | Works when |
|---|----------|------------|
| 1 | Export symbol lookup | Debug / unstripped `libflutter.so` |
| 2 | ARM64 pattern scan for `MOVZ W*, #0x86` | Production arm64 builds |
| 3 | Dart SSL socket export hooks | Some Flutter versions |
| 4 | Android `TrustManager` Java hooks | Hybrid apps with Java HTTP clients |

---

## Proxy Setup (Burp Suite / mitmproxy)

After applying either bypass, configure the device to use your proxy:

```bash
# Android — set proxy via adb
adb shell settings put global http_proxy 192.168.1.10:8080

# Or set Wi-Fi proxy manually in device Settings → Wi-Fi → Modify Network

# mitmproxy — start listener
mitmproxy --listen-port 8080

# Burp Suite — Proxy → Options → Add listener on 0.0.0.0:8080
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Could not locate ssl_verify_peer_cert` | Use `--info` to confirm it is a Flutter app; try `--offset` with a known offset from a disassembler |
| `No libflutter.so found` | The APK may use an App Bundle (`.aab`) — extract the APK set first with `bundletool` |
| App crashes after patch | The offset was wrong; try a different candidate offset reported by the tool |
| Frida script reports "incomplete" | App uses an unknown architecture — open an issue with the `--info` output |

---

## Legal Notice

This tool is intended for **authorised security testing** of applications you
own or have explicit written permission to test.  Unauthorised interception of
network traffic may violate the Computer Fraud and Abuse Act (CFAA), GDPR,
and other applicable laws.  The authors assume no liability for misuse.

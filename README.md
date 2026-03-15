# FlutteREngine — Flutter SSL Pinning Bypass + Runtime Offset Dumper

A security-research toolkit for disabling SSL certificate pinning in Flutter
Android apps and dumping Dart/BoringSSL function offsets — both statically
(via APK repackaging) and at runtime (via Frida).

| Tool | Method | Root required? |
|------|--------|----------------|
| `FlutteREngine.py` | Static patch + verbose offset dump | No |
| `patch_flutter.py` | Static binary patch (libflutter.so) | No |
| `frida_ssl_bypass.js` | Runtime hook via Frida | Yes (Frida server) |

---

## Quick Start — just run FlutteREngine

```bash
# Clone the repo
git clone https://github.com/r1skyb0x/FlutteREngine
cd FlutteREngine

# Patch an APK and dump all Dart/BoringSSL offsets in one command
python FlutteREngine.py target.apk
```

That single command will:
1. Detect the Flutter engine version
2. **Verbosely dump every Dart / BoringSSL offset** found in `libflutter.so`
3. Patch `ssl_verify_peer_cert` to always return success (0)
4. Re-pack and sign the APK → `target_patched.apk`
5. Print the Frida command for optional runtime hooking

---

## How SSL Pinning Works in Flutter

Flutter embeds **BoringSSL** inside `libflutter.so`. The function
`ssl_verify_peer_cert` validates the server's certificate chain and returns
an `ssl_verify_result_t` enum:

```
ssl_verify_ok      = 0   ← what we force it to always return
ssl_verify_invalid = 1
ssl_verify_retry   = 2
```

Both tools force this function to return `0` unconditionally, making the
Flutter engine accept any certificate — including self-signed proxy certs.

---

## Engine Version Database (`enginehash.csv`)

Maps Flutter release versions to their engine git commit and the MD5
"snapshot hash" embedded as a literal string in every `libflutter.so`.

| Column | Description |
|--------|-------------|
| `version` | Flutter SDK version string |
| `Engine_commit` | Full 40-char SHA-1 of the engine commit |
| `Snapshot_Hash` | MD5 string embedded inside `libflutter.so` |

---

## `FlutteREngine.py` — Easy All-In-One Entry Point

### Requirements

- Python 3.9+ (no third-party packages)
- `zipalign`, `apksigner` / `jarsigner`, `keytool` — optional, from Android SDK

### Usage

```bash
# Patch APK + dump all offsets (most common usage)
python FlutteREngine.py target.apk

# Dump Dart/BoringSSL offsets only — no patching, no repack
python FlutteREngine.py --dump-offsets target.apk

# Show Flutter version embedded in the APK
python FlutteREngine.py --info target.apk

# List all 62 known Flutter engine versions
python FlutteREngine.py --list-versions

# Show Frida command for runtime hooking
python FlutteREngine.py --frida target.apk

# Specify output path
python FlutteREngine.py target.apk -o ssl_free.apk

# Override the patch offset when auto-detection fails
python FlutteREngine.py target.apk --offset 0x1a2b3c
```

### Sample Output

```
[*] Target  : target.apk
[+] Engine DB : 62 known Flutter versions
──────────────────────────────────────────────────────────
[*] Processing: lib/arm64-v8a/libflutter.so  (ABI: arm64-v8a)
[+] Flutter version : 3.27.1  (engine commit cb4b5fff73850b2e…)
[*] Scanning for Dart / BoringSSL offsets …
[+] lib/arm64-v8a/libflutter.so — 5 offset(s) found:

  Offset        Symbol / Pattern                          Detail
  ─────────────────────────────────────────────────────────────────
  0x001a2b3c    ssl_verify_peer_cert                      BoringSSL cert-validation (patch target)
  0x001a2d10    MOVZ W*,#0x86 (SSL_R_CERTIFICATE_VERIFY_FAILED)  BoringSSL error constant load
  0x001a2d1c    0x14000086 (ERR_PACK SSL error)           BoringSSL packed error constant
  0x008f3200    version string (3.27.1)                   Embedded Flutter version string
  ...

[*] Patching ssl_verify_peer_cert …
[+] Patched ssl_verify_peer_cert @ 0x001a2b3c  (arm64: 00 00 80 d2 c0 03 5f d6)
[+] Patched 1 / 1 candidate(s)
...
[+] Patched APK  →  target_patched.apk
[*] Install  :  adb install -r "target_patched.apk"
[*] Runtime  :  frida -U -f <package> -l frida_ssl_bypass.js --no-pause
```

---

## `patch_flutter.py` — Static APK Patcher

Lower-level patcher with explicit offset control.

```bash
python patch_flutter.py target.apk              # → target_patched.apk
python patch_flutter.py --info target.apk       # identify Flutter version
python patch_flutter.py target.apk -o out.apk  # custom output path
python patch_flutter.py target.apk --offset 0x1a2b3c  # manual offset
python patch_flutter.py --list-versions         # show all 62 known versions
```

### Detection strategy per architecture

| Arch | Search pattern | Patch |
|------|----------------|-------|
| arm64-v8a | `MOVZ W*, #0x86` (`[C0-CF] 10 80 52`) → walk back to `STP X29,X30` prologue | `MOVZ X0,#0 ; RET` (8 B) |
| armeabi-v7a | Thumb-2 MOVW + packed error const → PUSH prologue | `MOVS R0,#0 ; BX LR` (4 B) |
| x86_64 / x86 | Packed `0x14000086` constant → PUSH RBP prologue | `XOR EAX,EAX ; RET` (3 B) |

---

## `frida_ssl_bypass.js` — Runtime Hook + Dart Offset Dumper

Attaches to a running Flutter process and:
1. **Dumps all Dart/BoringSSL offsets** (relative to `libflutter.so` base)
2. Patches `ssl_verify_peer_cert` using four layered strategies

### Requirements

- [Frida](https://frida.re) 16+ on your host machine
- `frida-server` running on the target Android device (root required)

### Usage

```bash
# Spawn and patch from the start (recommended)
frida -U -f com.example.app -l frida_ssl_bypass.js --no-pause

# Attach to a running process
frida -U -n com.example.app -l frida_ssl_bypass.js
frida -U --attach-pid 12345 -l frida_ssl_bypass.js

# iOS
frida -U -f com.example.app -l frida_ssl_bypass.js --no-pause
```

### Runtime Output (excerpt)

```
[FlutteREngine] [+] ═══ Runtime Dart/BoringSSL Offset Table (libflutter.so) ═══
  Offset        Abs Address          Symbol / Pattern                           Detail
  ─────────────────────────────────────────────────────────────────────────────────────
  0x001a2b3c    0x7a1c1a2b3c         ssl_verify_peer_cert (ARM64 prologue)      STP X29,X30 prologue …
  0x001a2d10    0x7a1c1a2d10         MOVZ W*,#0x86 (SSL_R_CERTIFICATE_VERIFY_FAILED)  BoringSSL error constant
  0x001a2d1c    0x7a1c1a2d1c         0x14000086 (ERR_PACK SSL error)            BoringSSL packed error
  ...
[FlutteREngine] [+] Total: 8 unique offset(s) found

[FlutteREngine] [+] ═══ Applying SSL Pinning Bypass ═══
[FlutteREngine] [+] Strategy 2: ssl_verify_peer_cert prologue @ 0x7a1c1a2b3c
[FlutteREngine] [+]   Patched: 00 00 80 d2 c0 03 5f d6
[FlutteREngine] [+] ✓ SSL pinning bypass applied successfully
```

### Strategies (applied in order)

| # | Strategy | Works when |
|---|----------|------------|
| 1 | Export symbol lookup | Debug / unstripped `libflutter.so` |
| 2 | ARM64 pattern scan (`MOVZ W*, #0x86`) | Production arm64 builds |
| 3 | Dart SSL socket export hooks | Some Flutter versions |
| 4 | Android `TrustManager` Java hooks | Hybrid apps with Java HTTP clients |

---

## Proxy Setup (Burp Suite / mitmproxy)

```bash
# Set proxy via adb
adb shell settings put global http_proxy 192.168.1.10:8080

# Start mitmproxy
mitmproxy --listen-port 8080

# Burp Suite → Proxy → Options → Listener on 0.0.0.0:8080

# Install the patched APK
adb install -r target_patched.apk
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ssl_verify_peer_cert not found` | Use `--dump-offsets` to inspect the binary; try `--offset` with a known value from a disassembler |
| `No libflutter.so found` | APK may be an App Bundle (`.aab`) — extract APK set first with `bundletool` |
| App crashes after patch | The offset was wrong; look at the full offset table and try a different candidate |
| Frida script reports "incomplete" | Unknown architecture — use `--dump-offsets` and report the output as an issue |
| Version shows "unknown" | Hash not yet in `enginehash.csv`; the patch may still work via pattern scan |

---

## Legal Notice

This tool is intended for **authorised security testing** of applications you
own or have explicit written permission to test. Unauthorised interception of
network traffic may violate the Computer Fraud and Abuse Act (CFAA), GDPR,
and other applicable laws. The authors assume no liability for misuse.

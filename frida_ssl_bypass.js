/**
 * FlutteREngine — Frida SSL Pinning Bypass Script
 * ================================================
 * Runtime hook for Flutter Android/iOS apps that disables SSL certificate
 * pinning by patching ssl_verify_peer_cert inside libflutter.so.
 *
 * Usage (Android):
 *   frida -U -f com.example.app -l frida_ssl_bypass.js --no-pause
 *   frida -U --attach-pid <PID> -l frida_ssl_bypass.js
 *
 * Usage (iOS):
 *   frida -U -f com.example.app -l frida_ssl_bypass.js --no-pause
 *
 * The script supports multiple detection strategies and falls back
 * gracefully when a method is not available on the target platform.
 */

"use strict";

// ── Configuration ────────────────────────────────────────────────────────────

const CONFIG = {
  // Name of the Flutter engine shared library
  flutterLib: Process.platform === "darwin" ? "Flutter" : "libflutter.so",

  // ARM64 byte sequence for ssl_verify_peer_cert function prologue search.
  // Pattern: STP X29, X30, [SP, #-N]!  (standard ARM64 frame setup)
  arm64Prologue: [0xFD, 0x7B],          // first 2 bytes (wildcard for N)

  // Immediate return patch sequences keyed by arch (replaces function body)
  patches: {
    arm64:  [0x00, 0x00, 0x80, 0xD2,   // MOVZ X0, #0
             0xC0, 0x03, 0x5F, 0xD6],  // RET
    arm:    [0x00, 0x00, 0xA0, 0xE3,   // MOV  R0, #0  (ARM mode)
             0x1E, 0xFF, 0x2F, 0xE1],  // BX   LR
    thumb:  [0x00, 0x20,               // MOVS R0, #0  (Thumb mode)
             0x70, 0x47],              // BX   LR
    x86:    [0x31, 0xC0, 0xC3],        // XOR EAX,EAX ; RET
    x86_64: [0x31, 0xC0, 0xC3],        // XOR EAX,EAX ; RET
  },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function log(msg)  { console.log(`[FlutteREngine] ${msg}`); }
function warn(msg) { console.warn(`[FlutteREngine] WARN  ${msg}`); }
function err(msg)  { console.error(`[FlutteREngine] ERROR ${msg}`); }

/** Convert a byte array to a hex string for display. */
function bytesToHex(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join(" ");
}

/** Write a patch byte array at a NativePointer address. */
function writePatch(addr, patchBytes) {
  try {
    Memory.protect(addr, patchBytes.length, "rwx");
    addr.writeByteArray(patchBytes);
    return true;
  } catch (e) {
    warn(`writePatch at ${addr}: ${e.message}`);
    return false;
  }
}

/** Return the architecture string for the current process. */
function currentArch() {
  const a = Process.arch;
  if (a === "arm64")   return "arm64";
  if (a === "arm")     return "arm";      // will check Thumb at call site
  if (a === "ia32")    return "x86";
  if (a === "x64")     return "x86_64";
  return a;
}

// ── Strategy 1: Export symbol lookup ─────────────────────────────────────────

/**
 * Try to resolve ssl_verify_peer_cert by its exported symbol name.
 * Flutter's libflutter.so is usually stripped, so this only works
 * in debug / unstripped builds.
 */
function patchByExport(module) {
  const sym = module.findExportByName("ssl_verify_peer_cert");
  if (!sym) {
    log("Export ssl_verify_peer_cert not found (stripped build)");
    return false;
  }
  const arch = currentArch();
  let patchArch = arch;
  let patchAddress = sym;

  // On 32-bit ARM, many builds use Thumb mode. Thumb function pointers
  // typically have bit 0 set; clear it for the actual code address and
  // select the Thumb patch bytes.
  if (arch === "arm") {
    try {
      if (!sym.isNull() && sym.and(1).toInt32() === 1) {
        patchArch = "thumb";
        patchAddress = sym.sub(1); // clear Thumb bit to get real code address
      }
    } catch (e) {
      warn(`Failed to determine ARM/Thumb mode for ${sym}: ${e.message}`);
    }
  }

  const patch = CONFIG.patches[patchArch] || CONFIG.patches["arm64"];
  log(`Strategy 1: found ssl_verify_peer_cert export @ ${patchAddress} (arch=${patchArch})`);
  if (writePatch(patchAddress, patch)) {
    log(`  Patched (${patchArch}): ${bytesToHex(patch)}`);
    return true;
  }
  return false;
}

// ── Strategy 2: Pattern scan for BoringSSL error constant ────────────────────

/**
 * BoringSSL embeds the constant SSL_R_CERTIFICATE_VERIFY_FAILED (0x86 = 134)
 * when reporting a certificate error.  We scan the .text section of
 * libflutter.so for the MOVZ W*, #0x86 ARM64 encoding and walk back to the
 * nearest function prologue.
 *
 * MOVZ W0..W15, #0x86, LSL #0  encodes as:  [C0-CF] 10 80 52
 */
function patchByPatternArm64(module) {
  // Byte pattern: MOVZ W*, #0x86  (ARM64, any dest register W0-W15)
  const pattern = "?? 10 80 52";          // ??  = C0..CF wildcard via Frida
  const prologueBytes = [0xFD, 0x7B];     // STP X29, X30 start bytes

  log("Strategy 2: scanning for MOVZ W*, #0x86 (SSL error constant) …");

  let found = false;
  Memory.scan(module.base, module.size, pattern, {
    onMatch(matchAddr) {
      // Walk backwards up to 0x800 bytes to find STP X29,X30 prologue
      const searchRange = 0x800;
      const searchStart = matchAddr.sub(searchRange);
      // Scan backwards (Frida scans forward, so we collect all matches
      // in the window and take the last one = nearest to our anchor)
      let lastPrologue = null;
      for (let off = 0; off < searchRange; off += 4) {
        const candidate = searchStart.add(off);
        try {
          const b0 = candidate.readU8();
          const b1 = candidate.add(1).readU8();
          const b3 = candidate.add(3).readU8();
          // STP X29, X30 : FD 7B ?? A9
          if (b0 === 0xFD && b1 === 0x7B && b3 === 0xA9) {
            lastPrologue = candidate;
          }
        } catch (_) { /* unreadable page */ }
      }

      if (lastPrologue) {
        log(`  Match @ ${matchAddr}  →  prologue @ ${lastPrologue}`);
        if (writePatch(lastPrologue, CONFIG.patches.arm64)) {
          log(`  Patched: ${bytesToHex(CONFIG.patches.arm64)}`);
          found = true;
        }
        return "stop"; // patch first occurrence; remove if multiple needed
      }
    },
    onComplete() {},
    onError(reason) { warn(`scan error: ${reason}`); },
  });

  return found;
}

// ── Strategy 3: Interceptor hook (non-destructive / always works) ─────────────

/**
 * Install an Interceptor that replaces the return value of every call
 * through libflutter.so pages that might be ssl_verify_peer_cert.
 * This is a best-effort hook used when static pattern matching fails.
 *
 * A more targeted version hooks the Dart SSL socket layer.
 */
function hookDartSslSocket() {
  // On some Flutter versions the Dart SSL layer exports these names.
  const targets = [
    "Dart_SetRootCertificates",
    "dart::bin::SecurityContext_SetAlpnProtocols",
  ];

  let hooked = false;
  for (const name of targets) {
    const addr = Module.findExportByName(CONFIG.flutterLib, name);
    if (addr) {
      Interceptor.attach(addr, {
        onLeave(retval) { retval.replace(ptr(0)); },
      });
      log(`Strategy 3: hooked ${name} → always return 0`);
      hooked = true;
    }
  }
  return hooked;
}

// ── Strategy 4: OkHttp / Conscrypt trust manager (Android Java layer) ─────────

/**
 * Hook Android's TrustManager checkServerTrusted to suppress certificate
 * errors in the Java/Kotlin layer (covers hybrid Flutter apps that use
 * native HTTP clients alongside Flutter's engine).
 */
function hookJavaTrustManager() {
  if (typeof Java === "undefined" || !Java.available) return false;

  Java.perform(() => {
    try {
      // Hook all TrustManager implementations
      const TrustManagerImpl = Java.use(
        "com.android.org.conscrypt.TrustManagerImpl");
      TrustManagerImpl.checkTrustedRecursive.overload(
        "[Ljava.security.cert.X509Certificate;",
        "java.lang.String", "int",
        "java.util.List", "java.util.List", "java.util.List"
      ).implementation = function () { return Java.use("java.util.ArrayList").$new(); };
      log("Strategy 4: hooked Conscrypt TrustManagerImpl.checkTrustedRecursive");
    } catch (_) { /* not available on all devices */ }

    try {
      const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
      const impls = Java.enumerateLoadedClassesSync()
        .filter(c => c.match(/TrustManager/i));
      for (const cls of impls) {
        try {
          const Cls = Java.use(cls);
          if (Cls.checkServerTrusted) {
            Cls.checkServerTrusted.overload(
              "[Ljava.security.cert.X509Certificate;", "java.lang.String"
            ).implementation = function () { /* noop = trust all */ };
          }
        } catch (_) {}
      }
    } catch (_) {}
  });

  return true;
}

// ── Main ──────────────────────────────────────────────────────────────────────

function main() {
  log("=== Flutter SSL Pinning Bypass ===");
  log(`Platform : ${Process.platform}  Arch : ${Process.arch}`);

  // Wait for libflutter.so to be loaded
  const tryPatch = () => {
    const mod = Process.findModuleByName(CONFIG.flutterLib);
    if (!mod) {
      warn(`${CONFIG.flutterLib} not loaded yet — retrying in 500 ms …`);
      setTimeout(tryPatch, 500);
      return;
    }

    log(`Module   : ${mod.name}  base=${mod.base}  size=0x${mod.size.toString(16)}`);

    let success = false;

    // Strategy 1: unstripped export
    success = patchByExport(mod) || success;

    // Strategy 2: ARM64 pattern scan (most common Flutter architecture)
    if (Process.arch === "arm64") {
      success = patchByPatternArm64(mod) || success;
    }

    // Strategy 3: Dart SSL socket hooks
    success = hookDartSslSocket() || success;

    // Strategy 4: Java TrustManager (Android only)
    if (Process.platform === "linux") {   // Android presents as "linux"
      hookJavaTrustManager();
    }

    if (success) {
      log("SSL pinning bypass applied ✓");
    } else {
      warn("Automatic bypass may be incomplete.");
      warn("Try: python patch_flutter.py --info app.apk  to identify the");
      warn("     Flutter version, then supply --offset manually.");
    }
  };

  tryPatch();
}

main();

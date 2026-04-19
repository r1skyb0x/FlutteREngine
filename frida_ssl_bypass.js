/**
 * FlutteREngine — Frida SSL Pinning Bypass + Runtime Dart Offset Dumper
 * ======================================================================
 * Attaches to a Flutter Android/iOS app, dumps all Dart/BoringSSL
 * function offsets from libflutter.so at runtime, then patches
 * ssl_verify_peer_cert so every TLS certificate is accepted.
 *
 * Usage (Android — spawn):
 *   frida -U -f com.example.app -l frida_ssl_bypass.js --no-pause
 *
 * Usage (Android — attach to running process):
 *   frida -U -n com.example.app -l frida_ssl_bypass.js
 *   frida -U --attach-pid <PID> -l frida_ssl_bypass.js
 *
 * Usage (iOS):
 *   frida -U -f com.example.app -l frida_ssl_bypass.js --no-pause
 *
 * Strategies tried in order:
 *   1. Export symbol lookup (unstripped / debug builds)
 *   2. ARM64 pattern scan: MOVZ W*, #0x86  →  walk back to STP X29,X30
 *   3. Dart SSL socket export hooks
 *   4. Android Java TrustManager / Conscrypt hook (hybrid apps)
 */

"use strict";

// ── Configuration ─────────────────────────────────────────────────────────────

const CFG = {
  flutterLib:  Process.platform === "darwin" ? "Flutter" : "libflutter.so",
  appLib:      "libapp.so",
  maxScanBack: 0x800,   // bytes to walk back for prologue search

  // Immediate-return patches keyed by architecture
  patches: {
    arm64:  [0x00, 0x00, 0x80, 0xD2,   // MOVZ X0, #0
             0xC0, 0x03, 0x5F, 0xD6],  // RET
    arm:    [0x00, 0x00, 0xA0, 0xE3,   // MOV  R0, #0  (ARM)
             0x1E, 0xFF, 0x2F, 0xE1],  // BX   LR
    thumb:  [0x00, 0x20,               // MOVS R0, #0  (Thumb-2)
             0x70, 0x47],              // BX   LR
    x86:    [0x31, 0xC0, 0xC3],        // XOR EAX,EAX ; RET
    x86_64: [0x31, 0xC0, 0xC3],        // XOR EAX,EAX ; RET
  },
};

// ── Logging helpers ────────────────────────────────────────────────────────────

const TAG = "[FlutteREngine]";
function log(msg)  { console.log(`${TAG} [*] ${msg}`); }
function ok(msg)   { console.log(`${TAG} [+] ${msg}`); }
function warn(msg) { console.warn(`${TAG} [!] ${msg}`); }
function err(msg)  { console.error(`${TAG} [-] ${msg}`); }

function hex(n) { return "0x" + n.toString(16).padStart(8, "0"); }
function bytesToHex(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join(" ");
}

// ── Low-level helpers ──────────────────────────────────────────────────────────

function writePatch(addr, patchBytes) {
  try {
    Memory.protect(addr, patchBytes.length, "rwx");
    addr.writeByteArray(patchBytes);
    return true;
  } catch (e) {
    warn(`writePatch @ ${addr}: ${e.message}`);
    return false;
  }
}

function readU8Safe(addr) {
  try { return addr.readU8(); } catch (_) { return null; }
}

function currentPatch() {
  const a = Process.arch;
  if (a === "arm64")  return CFG.patches.arm64;
  if (a === "arm")    return CFG.patches.thumb;
  if (a === "ia32")   return CFG.patches.x86;
  if (a === "x64")    return CFG.patches.x86_64;
  return CFG.patches.arm64;
}

// ── Runtime Dart Offset Dumper ─────────────────────────────────────────────────
//
// Scans libflutter.so at runtime and logs all Dart/BoringSSL offsets in a
// formatted table.  This is the "verbose dump offset from .dart during runtime"
// feature.

/**
 * Walk backwards from `anchorAddr` (inside the module's memory range) looking
 * for the nearest STP X29, X30 ARM64 function prologue.
 *
 * STP X29, X30, [SP, #-N]! encodes as: FD 7B ?? A9  (4-byte aligned)
 *
 * Returns the prologue NativePointer or null.
 */
function findArm64Prologue(anchorAddr, moduleBase) {
  const searchLen = Math.min(CFG.maxScanBack,
                             anchorAddr.sub(moduleBase).toInt32());
  let best = null;
  for (let off = 4; off <= searchLen; off += 4) {
    const cand = anchorAddr.sub(off);
    const b0 = readU8Safe(cand);
    const b1 = readU8Safe(cand.add(1));
    const b3 = readU8Safe(cand.add(3));
    if (b0 === 0xFD && b1 === 0x7B && b3 === 0xA9) {
      best = cand;   // keep scanning — want the nearest one
    }
  }
  return best;
}

/**
 * Scan libflutter.so for all DART / BoringSSL relevant addresses and print
 * a verbose offset table to the Frida console.
 *
 * Patterns scanned:
 *   - MOVZ W*, #0x86   → ARM64 ssl_verify_peer_cert candidate
 *   - ssl_verify_peer_cert export (if unstripped)
 *   - Dart_* and dart::* exports
 *   - libapp.so Dart AOT exports
 */
function dumpDartOffsets(flutterMod) {
  const base    = flutterMod.base;
  const modSize = flutterMod.size;
  const rows    = [];   // { offset, absAddr, name, detail }

  // ── 1. Named exports from libflutter.so ─────────────────────────────────
  log("Enumerating exports from " + flutterMod.name + " …");
  const dartRelated = /ssl|dart|flutter|boringssl|certificate/i;
  flutterMod.enumerateExports().forEach(exp => {
    if (dartRelated.test(exp.name)) {
      const relOff = exp.address.sub(base).toInt32();
      rows.push({
        offset:  relOff,
        absAddr: exp.address,
        name:    exp.name,
        detail:  "exported symbol",
      });
    }
  });

  // ── 2. ARM64: scan for MOVZ W*, #0x86  (SSL_R_CERTIFICATE_VERIFY_FAILED) ─
  //    MOVZ W<n>, #0x86 (n=0..15) encodes (LE) as:  [C0-CF] 10 80 52
  if (Process.arch === "arm64") {
    log("Scanning for MOVZ W*, #0x86 (SSL error constant) …");
    Memory.scan(base, modSize, "?? 10 80 52", {
      onMatch(matchAddr) {
        // Validate byte 0 is in range C0-DF (register W0-W30)
        const b0 = readU8Safe(matchAddr);
        // MOVZ W<n>, #0x86 encodes byte0 as 0xC0|n for n=0..15 ([C0-CF])
        if (b0 === null || b0 < 0xC0 || b0 > 0xCF) return;

        const relMatch = matchAddr.sub(base).toInt32();
        rows.push({
          offset:  relMatch,
          absAddr: matchAddr,
          name:    "MOVZ W*,#0x86 (SSL_R_CERTIFICATE_VERIFY_FAILED)",
          detail:  "BoringSSL error constant load",
        });

        // Walk back to prologue → that is ssl_verify_peer_cert
        const prologue = findArm64Prologue(matchAddr, base);
        if (prologue) {
          const relPro = prologue.sub(base).toInt32();
          rows.push({
            offset:  relPro,
            absAddr: prologue,
            name:    "ssl_verify_peer_cert (ARM64 prologue)",
            detail:  `STP X29,X30 prologue ${hex(relMatch - relPro)} B before anchor`,
          });
        }
      },
      onComplete() {},
      onError(reason) { warn("scan error: " + reason); },
    });

    // Also scan for the packed BoringSSL error: 0x14000086
    log("Scanning for packed SSL error constant (0x14000086) …");
    Memory.scan(base, modSize, "86 00 00 14", {
      onMatch(matchAddr) {
        const relOff = matchAddr.sub(base).toInt32();
        rows.push({
          offset:  relOff,
          absAddr: matchAddr,
          name:    "0x14000086 (ERR_PACK SSL error)",
          detail:  "BoringSSL packed error constant",
        });
      },
      onComplete() {},
      onError() {},
    });
  }

  // ── 3. libapp.so: Dart AOT snapshot exports ──────────────────────────────
  const appMod = Process.findModuleByName(CFG.appLib);
  if (appMod) {
    log("Enumerating Dart AOT exports from " + CFG.appLib + " …");
    appMod.enumerateExports().slice(0, 50).forEach(exp => {
      rows.push({
        offset:  exp.address.sub(appMod.base).toInt32(),
        absAddr: exp.address,
        name:    "[libapp] " + exp.name,
        detail:  "Dart AOT symbol",
      });
    });
    if (appMod.enumerateExports().length > 50) {
      rows.push({
        offset: 0, absAddr: appMod.base,
        name: "[libapp] … (truncated, showing first 50)",
        detail: "",
      });
    }
  }

  // ── Print table ───────────────────────────────────────────────────────────
  rows.sort((a, b) => a.offset - b.offset);

  const COL_OFF  = 12;
  const COL_ABS  = 18;
  const COL_NAME = Math.min(60, Math.max(30,
                    ...rows.map(r => r.name.length)));

  const sep = "  " + "-".repeat(COL_OFF + COL_ABS + COL_NAME + 12);
  const hdr = `  ${"Offset".padEnd(COL_OFF)}  ${"Abs Address".padEnd(COL_ABS)}  ${"Symbol / Pattern".padEnd(COL_NAME)}  Detail`;

  console.log("");
  ok("═══ Runtime Dart/BoringSSL Offset Table (" + flutterMod.name + ") ═══");
  console.log(hdr);
  console.log(sep);

  const seen = new Set();
  for (const r of rows) {
    const key = r.offset + ":" + r.name;
    if (seen.has(key)) continue;
    seen.add(key);

    const offStr = hex(r.offset).padEnd(COL_OFF);
    const absStr = r.absAddr.toString().padEnd(COL_ABS);
    const nameStr = r.name.padEnd(COL_NAME);
    console.log(`  ${offStr}  ${absStr}  ${nameStr}  ${r.detail}`);
  }

  console.log(sep);
  ok("Total: " + seen.size + " unique offset(s) found");
  console.log("");

  return rows;
}

// ── Strategy 1: Export symbol lookup ──────────────────────────────────────────

function patchByExport(mod) {
  const sym = mod.findExportByName("ssl_verify_peer_cert");
  if (!sym) {
    log("Strategy 1: ssl_verify_peer_cert export not found (stripped build)");
    return false;
  }
  const patch = currentPatch();
  ok(`Strategy 1: ssl_verify_peer_cert export @ ${sym}  offset=${hex(sym.sub(mod.base).toInt32())}`);
  if (writePatch(sym, patch)) {
    ok(`  Patched: ${bytesToHex(patch)}`);
    return true;
  }
  return false;
}

// ── Strategy 2: ARM64 pattern scan + prologue walk-back ───────────────────────

function patchByPatternArm64(mod) {
  if (Process.arch !== "arm64") return false;

  log("Strategy 2: scanning for MOVZ W*, #0x86 (ARM64) …");
  let found = false;

  Memory.scan(mod.base, mod.size, "?? 10 80 52", {
    onMatch(matchAddr) {
      const b0 = readU8Safe(matchAddr);
      // MOVZ W<n>, #0x86 encodes byte0 as 0xC0|n for n=0..15 ([C0-CF])
      if (b0 === null || b0 < 0xC0 || b0 > 0xCF) return;

      const prologue = findArm64Prologue(matchAddr, mod.base);
      if (!prologue) return;

      const relPro   = prologue.sub(mod.base).toInt32();
      const relMatch = matchAddr.sub(mod.base).toInt32();
      ok(`Strategy 2: ssl_verify_peer_cert prologue @ ${prologue}  (offset ${hex(relPro)})`);
      log(`  MOVZ anchor: ${matchAddr}  (offset ${hex(relMatch)})`);

      if (writePatch(prologue, CFG.patches.arm64)) {
        ok(`  Patched: ${bytesToHex(CFG.patches.arm64)}`);
        found = true;
      }
      return "stop";  // patch first occurrence only
    },
    onComplete() {},
    onError(reason) { warn("scan error: " + reason); },
  });

  return found;
}

// ── Strategy 3: Dart SSL socket export hooks ───────────────────────────────────

function hookDartSslExports() {
  const targets = [
    "Dart_SetRootCertificates",
    "dart::bin::SecurityContext_SetAlpnProtocols",
    "_dart_ssl_set_alpn_callback",
  ];
  let hooked = false;
  for (const name of targets) {
    const addr = Module.findExportByName(CFG.flutterLib, name);
    if (addr) {
      Interceptor.attach(addr, {
        onLeave(retval) { retval.replace(ptr(0)); },
      });
      ok(`Strategy 3: hooked ${name} @ ${addr} → always return 0`);
      hooked = true;
    }
  }
  if (!hooked) log("Strategy 3: no Dart SSL socket exports found");
  return hooked;
}

// ── Strategy 4: Android Java TrustManager ─────────────────────────────────────

function hookJavaTrustManager() {
  if (typeof Java === "undefined" || !Java.available) return false;

  Java.perform(() => {
    // Conscrypt
    try {
      const TM = Java.use("com.android.org.conscrypt.TrustManagerImpl");
      TM.checkTrustedRecursive.overload(
        "[Ljava.security.cert.X509Certificate;",
        "java.lang.String", "int",
        "java.util.List", "java.util.List", "java.util.List"
      ).implementation = function () {
        return Java.use("java.util.ArrayList").$new();
      };
      ok("Strategy 4: hooked Conscrypt TrustManagerImpl.checkTrustedRecursive");
    } catch (_) { /* not on all devices */ }

    // Generic TrustManager implementations
    try {
      const classes = Java.enumerateLoadedClassesSync()
                         .filter(c => /TrustManager/i.test(c));
      for (const cls of classes) {
        try {
          const Cls = Java.use(cls);
          if (Cls.checkServerTrusted) {
            Cls.checkServerTrusted.overload(
              "[Ljava.security.cert.X509Certificate;", "java.lang.String"
            ).implementation = function () { /* noop → trust all */ };
            ok(`Strategy 4: hooked ${cls}.checkServerTrusted`);
          }
        } catch (_) { /* skip */ }
      }
    } catch (_) { /* enumerateLoadedClassesSync unavailable */ }
  });

  return true;
}

// ── Main ───────────────────────────────────────────────────────────────────────

function main() {
  console.log("");
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║  FlutteREngine — SSL Bypass + Runtime Dart Offset Dumper    ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");
  log(`Platform: ${Process.platform}  Arch: ${Process.arch}  PID: ${Process.id}`);
  console.log("");

  function tryPatch() {
    const mod = Process.findModuleByName(CFG.flutterLib);
    if (!mod) {
      warn(`${CFG.flutterLib} not loaded yet — retrying in 500 ms …`);
      setTimeout(tryPatch, 500);
      return;
    }

    ok(`Module: ${mod.name}  base=${mod.base}  size=${hex(mod.size)}`);
    console.log("");

    // ── STEP 1: Dump all Dart/BoringSSL offsets verbosely ───────────────
    dumpDartOffsets(mod);

    // ── STEP 2: Apply SSL bypass patches ────────────────────────────────
    ok("═══ Applying SSL Pinning Bypass ═══");
    console.log("");

    let success = false;

    // Strategy 1: exported symbol (debug/unstripped builds)
    success = patchByExport(mod) || success;

    // Strategy 2: ARM64 binary pattern scan
    if (Process.arch === "arm64") {
      success = patchByPatternArm64(mod) || success;
    }

    // Strategy 3: Dart SSL socket hooks
    success = hookDartSslExports() || success;

    // Strategy 4: Java TrustManager (Android)
    if (Process.platform === "linux") {  // Android presents as "linux"
      hookJavaTrustManager();
    }

    console.log("");
    if (success) {
      ok("✓ SSL pinning bypass applied successfully");
      log("You can now proxy HTTPS traffic through Burp Suite / mitmproxy.");
    } else {
      warn("Automatic bypass may be incomplete.");
      warn("Try: python FlutteREngine.py --dump-offsets app.apk");
      warn("     then supply the offset manually via --offset <hex>");
    }
    console.log("");
  }

  tryPatch();
}

main();

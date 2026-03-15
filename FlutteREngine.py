#!/usr/bin/env python3
"""
FlutteREngine — Flutter SSL Pinning Bypass + Verbose Runtime Offset Dumper
==========================================================================
All-in-one tool: patch a Flutter APK and dump every relevant offset from
libflutter.so in a single command.

Usage
-----
  python FlutteREngine.py target.apk          # patch + dump offsets (default)
  python FlutteREngine.py --info target.apk   # version info only
  python FlutteREngine.py --dump-offsets target.apk   # dump offsets, no patch
  python FlutteREngine.py --list-versions     # list all known Flutter versions
  python FlutteREngine.py --frida target.apk  # show Frida one-liner for the APK

Requirements: Python 3.9+ (stdlib only).
Optional    : zipalign, apksigner / jarsigner, keytool  (APK signing).
              Frida  (https://frida.re)  for the --frida runtime option.
"""

from __future__ import annotations

import argparse
import csv
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent.resolve()
ENGINE_HASH_CSV = SCRIPT_DIR / "enginehash.csv"
FRIDA_SCRIPT    = SCRIPT_DIR / "frida_ssl_bypass.js"

# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------

def _info(msg: str)  -> None: print(f"[*] {msg}")
def _ok(msg: str)    -> None: print(f"[+] {msg}")
def _warn(msg: str)  -> None: print(f"[!] {msg}")
def _err(msg: str)   -> None: print(f"[-] {msg}", file=sys.stderr)

def _banner() -> None:
    print(r"""
  _____ _      _   _           _____ ______             _
 |  ___| |    | | | |         |  ___||  _  \           (_)
 | |_  | |    | | | |_ ___    | |__  | | | |_ __   __ _ _ _ __   ___
 |  _| | |    | | | __/ _ \   |  __| | | | | '_ \ / _` | | '_ \ / _ \
 | |   | |____| |_| ||  __/   | |___ | |/ /| | | | (_| | | | | |  __/
 \_|   \_____/ \___/ \___/    \____/ |___/ |_| |_|\__, |_|_| |_|\___|
                                                    __/ |
  Flutter SSL Bypass + Runtime Offset Dumper       |___/
""")

# ---------------------------------------------------------------------------
# Architecture-specific NOP-return patches
# ---------------------------------------------------------------------------
PATCH_ARM64       = bytes([0x00, 0x00, 0x80, 0xD2,  # MOVZ X0, #0
                            0xC0, 0x03, 0x5F, 0xD6]) # RET
PATCH_ARM32_THUMB = bytes([0x00, 0x20,               # MOVS R0, #0
                            0x70, 0x47])              # BX LR
PATCH_ARM32_ARM   = bytes([0x00, 0x00, 0xA0, 0xE3,  # MOV R0, #0
                            0x1E, 0xFF, 0x2F, 0xE1]) # BX LR
PATCH_X86         = bytes([0x31, 0xC0, 0xC3])        # XOR EAX,EAX ; RET

_ARCH_PATCHES: dict[str, bytes] = {
    "arm64":  PATCH_ARM64,
    "arm32":  PATCH_ARM32_THUMB,
    "x86_64": PATCH_X86,
    "x86":    PATCH_X86,
}

# ---------------------------------------------------------------------------
# BoringSSL / Dart offset patterns
# ---------------------------------------------------------------------------
# ssl_verify_peer_cert constants:
#   SSL_R_CERTIFICATE_VERIFY_FAILED = 0x86 (134)
#   ERR_LIB_SSL                     = 0x14  (20)
#
# ARM64  MOVZ W*, #0x86  →  bytes  [C0-CF] 10 80 52  (Rd = W0..W15)
# ARM64  MOVZ W*, #0x14  →  bytes  [80-8F] 02 80 52
# ARM64  STP X29, X30, [SP, #-N]!  →  FD 7B [BC-BF] A9  (function prologue)
# ARM32T MOVW R*, #0x86  →  40 F2 86 0*
# x86/64 packed constant  0x14000086
_ARM64_MOVZ_0x86 = re.compile(rb'[\xC0-\xCF]\x10\x80\x52')
_ARM64_MOVZ_0x14 = re.compile(rb'[\x80-\x8F]\x02\x80\x52')
_ARM64_PROLOGUE  = re.compile(rb'\xFD\x7B[\xBC-\xBF]\xA9')
_ARM32T_PUSH_LR  = re.compile(rb'\x2D\xE9[\x00-\xFF][\x40-\x7F]')
_X86_PUSH_RBP    = re.compile(rb'\x55')
_SSL_ERR_PACKED  = struct.pack('<I', 0x14000086)

# Dart VM snapshot identifier string embedded in libflutter.so
_DART_VM_PRODUCT = re.compile(rb'dart-sdk/lib/[^\x00]{4,80}')
_FLUTTER_VER_STR = re.compile(rb'\b(\d+\.\d+\.\d+[\w.+\-]*)\b')

# ---------------------------------------------------------------------------
# Engine version database
# ---------------------------------------------------------------------------

def load_engine_db() -> dict[str, dict]:
    """Return {snapshot_hash → {version, commit}} from enginehash.csv."""
    db: dict[str, dict] = {}
    if not ENGINE_HASH_CSV.exists():
        return db
    with open(ENGINE_HASH_CSV, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            snap = row.get("Snapshot_Hash", "").strip()
            ver  = row.get("version", "").strip()
            cmt  = row.get("Engine_commit", "").strip()
            if snap:
                db[snap] = {"version": ver, "commit": cmt}
    return db


def identify_version(lib_data: bytes, db: dict[str, dict]) -> dict | None:
    """Search libflutter.so bytes for a known 32-hex snapshot hash string."""
    for m in re.finditer(rb'[0-9a-f]{32}', lib_data):
        candidate = m.group(0).decode()
        if candidate in db:
            return db[candidate]
    return None

# ---------------------------------------------------------------------------
# ELF helpers
# ---------------------------------------------------------------------------

def elf_arch(data: bytes) -> str:
    """Return ELF machine architecture string."""
    if len(data) < 20 or data[:4] != b'\x7fELF':
        return "unknown"
    e_machine = struct.unpack_from('<H', data, 18)[0]
    return {183: "arm64", 40: "arm32", 62: "x86_64", 3: "x86"}.get(
        e_machine, "unknown")

# ---------------------------------------------------------------------------
# Offset finders — static analysis of libflutter.so bytes
# ---------------------------------------------------------------------------

def _walk_back(data: bytes, anchor: int, pat: re.Pattern,
               max_dist: int = 0x800) -> list[int]:
    """Return the last pattern match before *anchor* within *max_dist* bytes."""
    start = max(0, anchor - max_dist)
    hits  = list(pat.finditer(data[start:anchor]))
    return [start + h.start() for h in hits[-1:]]  # only the nearest


def _find_ssl_offsets_arm64(data: bytes) -> list[int]:
    anchors: list[int] = []
    for pat in (_ARM64_MOVZ_0x86, _ARM64_MOVZ_0x14):
        for m in pat.finditer(data):
            anchors.append(m.start())
    for m in re.finditer(re.escape(_SSL_ERR_PACKED), data):
        anchors.append(m.start())

    seen: set[int] = set()
    offsets: list[int] = []
    for a in anchors:
        for off in _walk_back(data, a, _ARM64_PROLOGUE):
            if off % 4 == 0 and off not in seen:
                seen.add(off)
                offsets.append(off)
    return sorted(offsets)


def _find_ssl_offsets_arm32(data: bytes) -> list[int]:
    anchors: list[int] = []
    for m in re.finditer(re.escape(_SSL_ERR_PACKED), data):
        anchors.append(m.start())
    for m in re.finditer(rb'\x40\xF2\x86[\x00-\x0F]', data):
        anchors.append(m.start())

    seen: set[int] = set()
    offsets: list[int] = []
    for a in anchors:
        for off in _walk_back(data, a, _ARM32T_PUSH_LR):
            if off not in seen:
                seen.add(off)
                offsets.append(off)
    return sorted(offsets)


def _find_ssl_offsets_x86(data: bytes) -> list[int]:
    anchors: list[int] = []
    for m in re.finditer(re.escape(_SSL_ERR_PACKED), data):
        anchors.append(m.start())
    for m in re.finditer(rb'\x86\x00\x00\x00', data):
        anchors.append(m.start())

    seen: set[int] = set()
    offsets: list[int] = []
    for a in anchors:
        for off in _walk_back(data, a, _X86_PUSH_RBP, max_dist=0x1000):
            if off not in seen:
                seen.add(off)
                offsets.append(off)
    return sorted(offsets)


def find_ssl_offsets(data: bytes, arch: str) -> list[int]:
    """Return candidate ssl_verify_peer_cert offsets for the given arch."""
    if arch == "arm64":  return _find_ssl_offsets_arm64(data)
    if arch == "arm32":  return _find_ssl_offsets_arm32(data)
    if arch in ("x86_64", "x86"):  return _find_ssl_offsets_x86(data)
    return []


def dump_dart_offsets(data: bytes, arch: str) -> list[dict]:
    """
    Scan libflutter.so for Dart-related strings and BoringSSL constants,
    returning a verbose table of discovered offsets.

    Each entry: {"name": str, "offset": int, "detail": str}
    """
    results: list[dict] = []

    # 1. ssl_verify_peer_cert candidates
    for off in find_ssl_offsets(data, arch):
        results.append({
            "name":   "ssl_verify_peer_cert",
            "offset": off,
            "detail": "BoringSSL cert-validation function (patch target)",
        })

    # 2. BoringSSL error constant anchors
    for m in re.finditer(re.escape(_SSL_ERR_PACKED), data):
        results.append({
            "name":   "SSL_R_CERTIFICATE_VERIFY_FAILED (0x14000086)",
            "offset": m.start(),
            "detail": "BoringSSL error constant reference",
        })

    # 3. Dart SDK path strings (useful for identifying Dart version)
    for m in _DART_VM_PRODUCT.finditer(data):
        try:
            text = m.group(0).decode("utf-8", errors="replace")
        except Exception:
            continue
        results.append({
            "name":   "dart-sdk path string",
            "offset": m.start(),
            "detail": text[:80],
        })

    # 4. Flutter version strings embedded in the binary
    seen_versions: set[str] = set()
    for m in _FLUTTER_VER_STR.finditer(data):
        ver = m.group(1).decode("utf-8", errors="replace")
        if ver not in seen_versions:
            seen_versions.add(ver)
            results.append({
                "name":   f"version string ({ver})",
                "offset": m.start(),
                "detail": "Embedded Flutter/Dart version string",
            })

    # Sort by offset for readability
    results.sort(key=lambda r: r["offset"])
    return results


# ---------------------------------------------------------------------------
# Verbose offset printer
# ---------------------------------------------------------------------------

def print_offset_table(entries: list[dict], lib_label: str) -> None:
    """Print a formatted table of discovered offsets."""
    if not entries:
        _warn(f"  {lib_label}: no Dart/BoringSSL offsets found")
        return

    _ok(f"  {lib_label} — {len(entries)} offset(s) found:")
    print()
    col_w = max(len(e["name"]) for e in entries)
    header = f"  {'Offset':<12}  {'Symbol / Pattern':<{col_w}}  Detail"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for e in entries:
        print(f"  0x{e['offset']:08x}    {e['name']:<{col_w}}  {e['detail']}")
    print()

# ---------------------------------------------------------------------------
# APK patching
# ---------------------------------------------------------------------------

def _apply_patch(buf: bytearray, offset: int, arch: str) -> bool:
    patch = _ARCH_PATCHES.get(arch)
    if patch is None or offset + len(patch) > len(buf):
        return False
    buf[offset: offset + len(patch)] = patch
    return True


def patch_lib(lib_path: Path, arch_hint: str | None,
              manual_offset: int | None) -> tuple[list[int], str]:
    """
    Find and patch ssl_verify_peer_cert in a libflutter.so.

    Returns (patched_offsets, status_message).
    """
    raw  = bytearray(lib_path.read_bytes())
    arch = elf_arch(bytes(raw))
    if arch == "unknown":
        arch = arch_hint or "unknown"
    if arch == "unknown":
        return [], "Cannot determine ELF architecture"

    _info(f"  Architecture : {arch}")

    if manual_offset is not None:
        offsets = [manual_offset]
        _info(f"  Manual offset: 0x{manual_offset:08x}")
    else:
        offsets = find_ssl_offsets(bytes(raw), arch)

    if not offsets:
        return [], "ssl_verify_peer_cert not found — try --offset <hex>"

    patched: list[int] = []
    for off in offsets:
        if _apply_patch(raw, off, arch):
            patched.append(off)
            _ok(f"  Patched ssl_verify_peer_cert @ 0x{off:08x}"
                f"  ({arch}: {_ARCH_PATCHES[arch].hex(' ')})")

    if patched:
        lib_path.write_bytes(bytes(raw))

    return patched, f"Patched {len(patched)} / {len(offsets)} candidate(s)"


def _make_debug_keystore(ks: Path) -> None:
    if ks.exists():
        return
    kt = shutil.which("keytool")
    if not kt:
        return
    subprocess.run(
        [kt, "-genkey", "-v",
         "-keystore", str(ks), "-alias", "androiddebugkey",
         "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
         "-storepass", "android", "-keypass", "android",
         "-dname", "CN=Android Debug,O=Android,C=US"],
        capture_output=True, check=False)


def repack_and_sign(orig: Path, work: Path, out: Path) -> bool:
    """Re-zip (native libs as STORE) and sign the patched APK."""
    unsigned = work / "_unsigned.apk"
    aligned  = work / "_aligned.apk"

    _info("Rebuilding APK …")
    with zipfile.ZipFile(orig, "r") as src, \
         zipfile.ZipFile(unsigned, "w") as dst:
        for info in src.infolist():
            local = work / info.filename
            compress = (zipfile.ZIP_STORED if info.filename.endswith(".so")
                        else zipfile.ZIP_DEFLATED)
            if local.is_file():
                dst.write(local, info.filename, compress_type=compress)
            else:
                dst.writestr(info, src.read(info.filename),
                             compress_type=compress)

    za = shutil.which("zipalign")
    if za:
        _info("Aligning APK …")
        r = subprocess.run([za, "-v", "4", str(unsigned), str(aligned)],
                           capture_output=True, text=True, check=False)
        if r.returncode != 0:
            _warn(f"zipalign: {r.stderr.strip()[:200]}")
            aligned = unsigned
    else:
        _warn("zipalign not found — skipping alignment")
        aligned = unsigned

    ks = work / "debug.keystore"
    _make_debug_keystore(ks)

    apksigner = shutil.which("apksigner")
    jarsigner = shutil.which("jarsigner")

    if apksigner:
        _info("Signing with apksigner …")
        r = subprocess.run(
            [apksigner, "sign",
             "--ks", str(ks), "--ks-pass", "pass:android",
             "--key-pass", "pass:android",
             "--out", str(out), str(aligned)],
            capture_output=True, text=True, check=False)
        if r.returncode != 0:
            _err(f"apksigner failed: {r.stderr.strip()[:300]}")
            return False
    elif jarsigner:
        _info("Signing with jarsigner …")
        shutil.copy(aligned, out)
        r = subprocess.run(
            [jarsigner, "-keystore", str(ks),
             "-storepass", "android", "-keypass", "android",
             str(out), "androiddebugkey"],
            capture_output=True, text=True, check=False)
        if r.returncode != 0:
            _err(f"jarsigner failed: {r.stderr.strip()[:300]}")
            return False
    else:
        _warn("No signing tool found — saving unsigned APK.")
        _warn("Sign manually before installing.")
        shutil.copy(aligned, out)

    return True

# ---------------------------------------------------------------------------
# High-level commands
# ---------------------------------------------------------------------------

def cmd_patch_and_dump(apk_path: Path, output_path: Path | None,
                       manual_offset: int | None,
                       dump_only: bool = False) -> bool:
    """
    Main pipeline:
      1. Extract APK
      2. For each libflutter.so:
         a. Identify Flutter version
         b. Dump all Dart / BoringSSL offsets verbosely
         c. Patch ssl_verify_peer_cert  (unless dump_only)
      3. Repack + sign  (unless dump_only)
    """
    if not apk_path.exists():
        _err(f"APK not found: {apk_path}")
        return False

    if output_path is None and not dump_only:
        output_path = apk_path.with_name(apk_path.stem + "_patched.apk")

    db = load_engine_db()

    print("=" * 70)
    _info(f"Target  : {apk_path}")
    if not dump_only:
        _info(f"Output  : {output_path}")
    _info(f"Engine DB : {len(db)} known Flutter versions")
    print("=" * 70)
    print()

    with tempfile.TemporaryDirectory(prefix="fre_") as tmp:
        work = Path(tmp)

        _info("Extracting APK …")
        with zipfile.ZipFile(apk_path, "r") as z:
            z.extractall(work)

        libs = sorted(work.rglob("libflutter.so"))
        if not libs:
            _err("No libflutter.so found — is this a Flutter app?")
            return False

        _ok(f"Found {len(libs)} libflutter.so slice(s)\n")

        any_patched = False
        for lib in libs:
            abi = lib.parent.name
            rel = lib.relative_to(work)
            print("-" * 60)
            _info(f"Processing: {rel}  (ABI: {abi})")

            raw = lib.read_bytes()

            # Version identification
            ver = identify_version(raw, db)
            if ver:
                _ok(f"Flutter version : {ver['version']}  "
                    f"(engine commit {ver['commit'][:16]}…)")
            else:
                _warn("Flutter version : unknown (hash not in DB)")

            # ── VERBOSE OFFSET DUMP ──────────────────────────────────────
            arch = elf_arch(raw)
            hint_map = {"arm64-v8a": "arm64", "armeabi-v7a": "arm32",
                        "x86_64": "x86_64", "x86": "x86"}
            if arch == "unknown":
                arch = hint_map.get(abi, "unknown")

            print()
            _info("Scanning for Dart / BoringSSL offsets …")
            entries = dump_dart_offsets(raw, arch)
            print_offset_table(entries, str(rel))

            if dump_only:
                continue

            # ── PATCH ────────────────────────────────────────────────────
            _info("Patching ssl_verify_peer_cert …")
            hint = hint_map.get(abi)
            patched_offs, msg = patch_lib(lib, hint, manual_offset)
            if patched_offs:
                _ok(msg)
                any_patched = True
            else:
                _warn(msg)

            print()

        if dump_only:
            return True

        if not any_patched:
            _err("No libraries were patched successfully.")
            return False

        print("-" * 60)
        _info("Repacking and signing …")
        if not repack_and_sign(apk_path, work, output_path):
            _err("Repack / sign failed.")
            return False

    print()
    print("=" * 70)
    _ok(f"Patched APK  →  {output_path}")
    _info(f"Install  :  adb install -r \"{output_path}\"")
    if FRIDA_SCRIPT.exists():
        _info(f"Runtime  :  frida -U -f <package> -l {FRIDA_SCRIPT} --no-pause")
    print("=" * 70)
    return True


def cmd_info(apk_path: Path) -> None:
    """Print Flutter version and architecture for each libflutter.so slice."""
    db = load_engine_db()
    _info(f"APK: {apk_path}\n")
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            if name.endswith("libflutter.so"):
                raw  = z.read(name)
                arch = elf_arch(raw)
                ver  = identify_version(raw, db)
                vstr = ver["version"] if ver else "unknown"
                cstr = (f"  commit {ver['commit'][:16]}…" if ver else "")
                print(f"  {name:<55s}  arch={arch:<8s}  Flutter={vstr}{cstr}")


def cmd_list_versions() -> None:
    db = load_engine_db()
    print(f"Known Flutter engine versions ({len(db)} entries):\n")
    seen: set[str] = set()
    for snap, info in db.items():
        v = info["version"]
        if v not in seen:
            seen.add(v)
            print(f"  {v:<32s}  engine {info['commit'][:16]}…  "
                  f"snapshot {snap}")


def cmd_frida(apk_path: Path) -> None:
    """Print the Frida invocation for this APK."""
    db = load_engine_db()
    pkg = "com.example.app"
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            # Try to read package name from AndroidManifest.xml (binary XML)
            if name == "AndroidManifest.xml":
                raw = z.read(name)
                # Binary XML: package name often follows 0x0004 (string chunk)
                m = re.search(rb'package\x00([\x20-\x7e]+)', raw)
                if m:
                    pkg = m.group(1).decode(errors="replace").split("\x00")[0]
                break

    _info(f"Package  : {pkg}")
    script = FRIDA_SCRIPT if FRIDA_SCRIPT.exists() else "frida_ssl_bypass.js"
    print()
    print("  # Spawn and patch from the start:")
    print(f"  frida -U -f {pkg} -l {script} --no-pause")
    print()
    print("  # Attach to a running process:")
    print(f"  frida -U -n {pkg} -l {script}")
    print()
    _info("The script dumps all Dart offsets and patches SSL verification at runtime.")

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="FlutteREngine",
        description="Flutter SSL Pinning Bypass + Verbose Runtime Offset Dumper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples
--------
  # Patch an APK and dump all Dart/BoringSSL offsets (most common usage)
  python FlutteREngine.py target.apk

  # Dump offsets only (no patching, no repack)
  python FlutteREngine.py --dump-offsets target.apk

  # Show Flutter version embedded in the APK
  python FlutteREngine.py --info target.apk

  # List all known Flutter engine versions in the local database
  python FlutteREngine.py --list-versions

  # Show Frida one-liner for runtime hooking
  python FlutteREngine.py --frida target.apk

  # Specify output APK path
  python FlutteREngine.py target.apk -o patched.apk

  # Override the patch offset when auto-detection fails
  python FlutteREngine.py target.apk --offset 0x1a2b3c
""")
    p.add_argument("apk", nargs="?", help="Flutter APK file to process")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Output patched APK path (default: <input>_patched.apk)")
    p.add_argument("--offset", metavar="HEX",
                   help="Manually specify ssl_verify_peer_cert offset (hex)")
    p.add_argument("--info", action="store_true",
                   help="Show Flutter version info from APK and exit")
    p.add_argument("--dump-offsets", action="store_true",
                   help="Dump Dart/BoringSSL offsets without patching")
    p.add_argument("--list-versions", action="store_true",
                   help="List all known Flutter engine versions and exit")
    p.add_argument("--frida", action="store_true",
                   help="Show Frida command for runtime hooking and exit")
    return p


def main(argv: list[str] | None = None) -> None:
    _banner()

    parser = _build_parser()
    args   = parser.parse_args(argv)

    if args.list_versions:
        cmd_list_versions()
        return

    if not args.apk:
        parser.print_help()
        sys.exit(1)

    apk = Path(args.apk)
    if not apk.exists():
        _err(f"File not found: {apk}")
        sys.exit(1)

    if args.info:
        cmd_info(apk)
        return

    if args.frida:
        cmd_frida(apk)
        return

    manual: int | None = None
    if args.offset:
        try:
            manual = int(args.offset, 16)
        except ValueError:
            _err(f"Invalid hex offset: {args.offset}")
            sys.exit(1)

    out = Path(args.output) if args.output else None

    success = cmd_patch_and_dump(
        apk, out, manual,
        dump_only=args.dump_offsets,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

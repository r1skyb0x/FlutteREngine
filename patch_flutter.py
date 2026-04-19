#!/usr/bin/env python3
"""
FlutteREngine SSL Pinning Bypass Auto-Patcher
==============================================
Automatically patches Flutter Android APKs to disable SSL certificate
pinning by finding and patching the BoringSSL ssl_verify_peer_cert
function inside libflutter.so.

Supported architectures : arm64-v8a  armeabi-v7a  x86_64  x86
Supported output formats: patched APK (re-signed with a debug key)

Usage
-----
  python patch_flutter.py target.apk
  python patch_flutter.py target.apk -o patched.apk
  python patch_flutter.py --info target.apk       # show version only
  python patch_flutter.py --list-versions         # dump known versions

Requirements: Python 3.9+ (stdlib only).
Optional    : zipalign, apksigner / jarsigner, keytool (for APK signing).
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

# ---------------------------------------------------------------------------
# Architecture-specific NOP-return patches
# ---------------------------------------------------------------------------
# ARM64 : MOVZ X0, #0  ;  RET
PATCH_ARM64 = bytes([0x00, 0x00, 0x80, 0xD2,   # MOVZ X0, #0
                     0xC0, 0x03, 0x5F, 0xD6])  # RET

# ARM32 Thumb-2 : MOVS R0, #0  ;  BX LR
PATCH_ARM32_THUMB = bytes([0x00, 0x20,   # MOVS R0, #0
                           0x70, 0x47])  # BX LR

# ARM32 ARM : MOV R0, #0  ;  BX LR
PATCH_ARM32_ARM = bytes([0x00, 0x00, 0xA0, 0xE3,   # MOV R0, #0
                         0x1E, 0xFF, 0x2F, 0xE1])  # BX LR

# x86 / x86_64 : XOR EAX, EAX  ;  RET
PATCH_X86 = bytes([0x31, 0xC0,   # XOR EAX, EAX
                   0xC3])        # RET

# ---------------------------------------------------------------------------
# Pattern helpers
# ---------------------------------------------------------------------------
# BoringSSL constants embedded in ssl_verify_peer_cert:
#   ERR_LIB_SSL                   = 20  (0x14)
#   SSL_R_CERTIFICATE_VERIFY_FAILED = 134 (0x86)
#
# ARM64  MOVZ W*, #0x86  →  [C0-CF] 10 80 52   (Rd = W0..W15)
# ARM64  MOVZ W*, #0x14  →  [80-8F] 02 80 52
# ARM32T MOVW R*, #0x86  →  40 F2 86 0*  (Thumb-2 MOVW)
# x86/64 MOV  [reg], 0x86 can appear as immediate in various encodings

_ARM64_MOVZ_0x86 = re.compile(rb'[\xC0-\xCF]\x10\x80\x52')
_ARM64_MOVZ_0x14 = re.compile(rb'[\x80-\x8F]\x02\x80\x52')
# ARM64 standard function prologue:  STP X29, X30, [SP, #-N]!
_ARM64_PROLOGUE = re.compile(rb'\xFD\x7B..\xA9')
# ARM32 Thumb PUSH {..., LR}
_ARM32T_PUSH_LR = re.compile(rb'\x2D\xE9[\x00-\xFF][\x40-\x7F]')
# x86/x86_64 function prologue: PUSH RBP / PUSH EBP  (0x55)
_X86_PUSH_RBP = re.compile(rb'\x55')

# 4-byte little-endian encoding of SSL_R_CERTIFICATE_VERIFY_FAILED error pack
# ERR_LIB_SSL<<24 | SSL_R_CERTIFICATE_VERIFY_FAILED  (used in some Flutter builds)
_SSL_ERR_PACKED = struct.pack('<I', 0x14000086)


# ---------------------------------------------------------------------------
# Engine database
# ---------------------------------------------------------------------------

def load_engine_database() -> dict[str, dict]:
    """Load version→snapshot_hash mapping from enginehash.csv."""
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


def identify_flutter_version(lib_data: bytes,
                             db: dict[str, dict]) -> dict | None:
    """Search libflutter.so for any known 32-hex snapshot hash."""
    for m in re.finditer(rb'[0-9a-f]{32}', lib_data):
        candidate = m.group(0).decode()
        if candidate in db:
            return db[candidate]
    return None


# ---------------------------------------------------------------------------
# ELF helpers
# ---------------------------------------------------------------------------

def elf_arch(data: bytes) -> str:
    """Return 'arm64', 'arm32', 'x86_64', 'x86', or 'unknown'."""
    if len(data) < 20 or data[:4] != b'\x7fELF':
        return 'unknown'
    e_machine = struct.unpack_from('<H', data, 18)[0]
    return {183: 'arm64', 40: 'arm32', 62: 'x86_64', 3: 'x86'}.get(
        e_machine, 'unknown')


# ---------------------------------------------------------------------------
# Offset finders
# ---------------------------------------------------------------------------

def _walk_back_to_prologue(data: bytes, anchor: int,
                            prologue_re: re.Pattern,
                            max_dist: int = 0x800) -> list[int]:
    """Find the last prologue match in the window before *anchor*."""
    start = max(0, anchor - max_dist)
    chunk = data[start:anchor]
    hits = list(prologue_re.finditer(chunk))
    if hits:
        return [start + hits[-1].start()]
    return []


def find_offsets_arm64(data: bytes) -> list[int]:
    """
    Strategy
    1. Find MOVZ W*, #0x86  (SSL_R_CERTIFICATE_VERIFY_FAILED load).
    2. Also search for the packed error constant 0x14000086.
    3. Walk back ≤ 0x800 bytes to the nearest STP X29,X30 prologue.
    4. All results must be 4-byte aligned.
    """
    anchors: list[int] = []

    for m in _ARM64_MOVZ_0x86.finditer(data):
        anchors.append(m.start())
    for m in _ARM64_MOVZ_0x14.finditer(data):
        anchors.append(m.start())
    for m in re.finditer(re.escape(_SSL_ERR_PACKED), data):
        anchors.append(m.start())

    offsets: list[int] = []
    for anchor in anchors:
        for off in _walk_back_to_prologue(data, anchor, _ARM64_PROLOGUE):
            if off % 4 == 0 and off not in offsets:
                offsets.append(off)
    return offsets


def find_offsets_arm32(data: bytes) -> list[int]:
    """
    Strategy: find PUSH {..,LR} prologue near the BoringSSL error constant.
    """
    anchors: list[int] = []
    for m in re.finditer(re.escape(_SSL_ERR_PACKED), data):
        anchors.append(m.start())
    # Thumb-2 MOVW load of 0x86 into any register: 40 F2 86 0*
    for m in re.finditer(rb'\x40\xF2\x86[\x00-\x0F]', data):
        anchors.append(m.start())

    offsets: list[int] = []
    for anchor in anchors:
        for off in _walk_back_to_prologue(data, anchor, _ARM32T_PUSH_LR):
            if off not in offsets:
                offsets.append(off)
    return offsets


def find_offsets_x86(data: bytes) -> list[int]:
    """
    Strategy: find PUSH RBP/EBP prologue near the BoringSSL error constant.
    """
    anchors: list[int] = []
    for m in re.finditer(re.escape(_SSL_ERR_PACKED), data):
        anchors.append(m.start())
    # Direct immediate 0x86 in MOV/CMP instructions (1-byte imm, little-endian)
    for m in re.finditer(rb'\x86\x00\x00\x00', data):
        anchors.append(m.start())

    offsets: list[int] = []
    for anchor in anchors:
        for off in _walk_back_to_prologue(data, anchor, _X86_PUSH_RBP,
                                          max_dist=0x1000):
            if off not in offsets:
                offsets.append(off)
    return offsets


def find_offsets(data: bytes, arch: str) -> list[int]:
    """Dispatcher — returns a list of candidate function start offsets."""
    if arch == 'arm64':
        return find_offsets_arm64(data)
    if arch == 'arm32':
        return find_offsets_arm32(data)
    if arch in ('x86_64', 'x86'):
        return find_offsets_x86(data)
    return []


# ---------------------------------------------------------------------------
# Patching
# ---------------------------------------------------------------------------

def apply_patch(buf: bytearray, offset: int, arch: str) -> bool:
    """Write the NOP-return patch into *buf* at *offset*."""
    patch = {
        'arm64':  PATCH_ARM64,
        'arm32':  PATCH_ARM32_THUMB,
        'x86_64': PATCH_X86,
        'x86':    PATCH_X86,
    }.get(arch)
    if patch is None:
        return False
    if offset + len(patch) > len(buf):
        return False
    buf[offset: offset + len(patch)] = patch
    return True


def patch_libflutter(lib_path: Path,
                     arch_hint: str | None = None,
                     manual_offset: int | None = None) -> tuple[bool, str]:
    """
    Patch a libflutter.so in-place.
    Returns (success, human-readable message).
    """
    raw = bytearray(lib_path.read_bytes())
    arch = elf_arch(bytes(raw))
    if arch == 'unknown':
        arch = arch_hint or 'unknown'
    if arch == 'unknown':
        return False, "Cannot determine ELF architecture"

    print(f"    [*] Architecture : {arch}")

    # ---- determine offsets ----
    if manual_offset is not None:
        offsets = [manual_offset]
        print(f"    [*] Using manual offset : 0x{manual_offset:08x}")
    else:
        offsets = find_offsets(bytes(raw), arch)

    if not offsets:
        return (False,
                "Could not locate ssl_verify_peer_cert — try --offset <hex>")

    print(f"    [*] Candidate offset(s): {[hex(o) for o in offsets]}")

    patched = 0
    for off in offsets:
        if apply_patch(raw, off, arch):
            print(f"    [+] Patched 0x{off:08x}")
            patched += 1

    if patched == 0:
        return False, "Patch write failed"

    lib_path.write_bytes(bytes(raw))
    return True, f"Patched {patched} location(s)"


# ---------------------------------------------------------------------------
# APK repack + sign
# ---------------------------------------------------------------------------

def _make_debug_keystore(ks: Path) -> None:
    """Generate a throwaway debug keystore with keytool (if available)."""
    if ks.exists():
        return
    kt = shutil.which("keytool")
    if not kt:
        return
    subprocess.run(
        [kt, "-genkey", "-v",
         "-keystore", str(ks),
         "-alias", "androiddebugkey",
         "-keyalg", "RSA", "-keysize", "2048",
         "-validity", "10000",
         "-storepass", "android", "-keypass", "android",
         "-dname", "CN=Android Debug,O=Android,C=US"],
        capture_output=True, check=False)


def repack_apk(original_apk: Path,
               work_dir: Path,
               output_apk: Path) -> bool:
    """
    Rebuild the APK from the modified work directory, then sign it.
    Native libraries (.so) are stored uncompressed (STORE) to remain
    compatible with Android's dlopen() on devices where extractNativeLibs=false.
    """
    unsigned = work_dir / "_unsigned.apk"
    aligned  = work_dir / "_aligned.apk"

    # --- rebuild ---
    print("    [*] Rebuilding APK …")
    with zipfile.ZipFile(original_apk, 'r') as src, \
         zipfile.ZipFile(unsigned, 'w') as dst:
        for info in src.infolist():
            local = work_dir / info.filename
            compress = (zipfile.ZIP_DEFLATED
                        if not info.filename.endswith(".so")
                        else zipfile.ZIP_STORED)
            if local.is_file():
                dst.write(local, info.filename, compress_type=compress)
            else:
                dst.writestr(info, src.read(info.filename),
                             compress_type=compress)

    # --- zipalign ---
    zipalign = shutil.which("zipalign")
    if zipalign:
        print("    [*] Aligning APK …")
        r = subprocess.run([zipalign, "-v", "4",
                            str(unsigned), str(aligned)],
                           capture_output=True, text=True, check=False)
        if r.returncode != 0:
            print(f"    [!] zipalign warning: {r.stderr.strip()[:200]}")
            aligned = unsigned
    else:
        print("    [!] zipalign not found — skipping alignment")
        aligned = unsigned

    # --- sign ---
    ks = work_dir / "debug.keystore"
    _make_debug_keystore(ks)

    apksigner  = shutil.which("apksigner")
    jarsigner  = shutil.which("jarsigner")

    if apksigner:
        print("    [*] Signing with apksigner …")
        r = subprocess.run(
            [apksigner, "sign",
             "--ks", str(ks),
             "--ks-pass", "pass:android",
             "--key-pass", "pass:android",
             "--out", str(output_apk),
             str(aligned)],
            capture_output=True, text=True, check=False)
        if r.returncode != 0:
            print(f"    [-] apksigner: {r.stderr.strip()[:300]}")
            return False

    elif jarsigner:
        print("    [*] Signing with jarsigner …")
        shutil.copy(aligned, output_apk)
        r = subprocess.run(
            [jarsigner,
             "-keystore", str(ks),
             "-storepass", "android", "-keypass", "android",
             str(output_apk), "androiddebugkey"],
            capture_output=True, text=True, check=False)
        if r.returncode != 0:
            print(f"    [-] jarsigner: {r.stderr.strip()[:300]}")
            return False

    else:
        print("    [!] No signing tool found (apksigner / jarsigner).")
        print("    [!] Copying unsigned APK — you must sign it manually.")
        shutil.copy(aligned, output_apk)

    return True


# ---------------------------------------------------------------------------
# Main patch routine
# ---------------------------------------------------------------------------

def patch_apk(apk_path: Path,
              output_path: Path | None,
              manual_offset: int | None = None) -> bool:
    """
    Full pipeline: extract → identify → patch → repack → sign.
    Returns True on success.
    """
    if not apk_path.exists():
        print(f"[-] APK not found: {apk_path}")
        return False

    if output_path is None:
        output_path = apk_path.with_name(apk_path.stem + "_patched.apk")

    print(f"[+] Input  : {apk_path}")
    print(f"[+] Output : {output_path}")

    db = load_engine_database()
    print(f"[*] Engine DB : {len(db)} known versions\n")

    with tempfile.TemporaryDirectory(prefix="fep_") as tmp:
        work = Path(tmp)

        # --- extract ---
        print("[*] Extracting APK …")
        with zipfile.ZipFile(apk_path, 'r') as z:
            z.extractall(work)

        # --- find libflutter.so ---
        libs = sorted(work.rglob("libflutter.so"))
        if not libs:
            print("[-] No libflutter.so found in APK — is this a Flutter app?")
            return False
        print(f"[*] Found {len(libs)} libflutter.so file(s)\n")

        any_patched = False
        for lib in libs:
            rel = lib.relative_to(work)
            print(f"[*] {rel}")

            # optional version identification
            ver = identify_flutter_version(lib.read_bytes(), db)
            if ver:
                print(f"    [+] Flutter {ver['version']}  "
                      f"engine {ver['commit'][:12]}…")
            else:
                print("    [!] Flutter version unknown "
                      "(snapshot hash not in DB)")

            # arch hint from ABI directory name
            abi = lib.parent.name
            hint_map = {"arm64-v8a": "arm64", "armeabi-v7a": "arm32",
                        "x86_64": "x86_64", "x86": "x86"}
            hint = hint_map.get(abi)

            ok, msg = patch_libflutter(lib, hint, manual_offset)
            (print(f"    [+] {msg}") if ok else print(f"    [-] {msg}"))
            if ok:
                any_patched = True
            print()

        if not any_patched:
            print("[-] No libraries were patched successfully.")
            return False

        # --- repack ---
        print("[*] Repacking …")
        if not repack_apk(apk_path, work, output_path):
            print("[-] Repack / sign failed.")
            return False

    print(f"\n[+] Done!  Patched APK → {output_path}")
    print(f"[*] Install : adb install -r \"{output_path}\"")
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="patch_flutter",
        description="Flutter SSL Pinning Bypass Auto-Patcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples
--------
  # Patch an APK (output: myapp_patched.apk)
  python patch_flutter.py myapp.apk

  # Specify output path
  python patch_flutter.py myapp.apk -o out.apk

  # Show Flutter version info without patching
  python patch_flutter.py --info myapp.apk

  # Override the patch offset (hex) — useful when auto-detection fails
  python patch_flutter.py myapp.apk --offset 0x1a2b3c

  # List known Flutter engine versions
  python patch_flutter.py --list-versions
""")
    p.add_argument("apk", nargs="?", help="Flutter APK to patch")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Output APK path  (default: <input>_patched.apk)")
    p.add_argument("--offset", metavar="HEX",
                   help="Manually specify hex offset of ssl_verify_peer_cert")
    p.add_argument("--info", action="store_true",
                   help="Print Flutter version info from APK and exit")
    p.add_argument("--list-versions", action="store_true",
                   help="List all known Flutter engine versions and exit")
    return p


def cmd_list_versions() -> None:
    db = load_engine_database()
    print(f"Known Flutter engine versions ({len(db)} entries):\n")
    seen: set[str] = set()
    for snap, info in db.items():
        v = info["version"]
        if v not in seen:
            seen.add(v)
            print(f"  {v:<30s}  engine {info['commit'][:16]}…  "
                  f"snapshot {snap}")


def cmd_info(apk_path: Path) -> None:
    db = load_engine_database()
    with zipfile.ZipFile(apk_path, 'r') as z:
        for name in z.namelist():
            if name.endswith("libflutter.so"):
                raw = z.read(name)
                arch = elf_arch(raw)
                ver  = identify_flutter_version(raw, db)
                vstr = ver["version"] if ver else "unknown"
                print(f"  {name:<60s}  arch={arch:<8s}  Flutter={vstr}")


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_versions:
        cmd_list_versions()
        return

    if not args.apk:
        parser.print_help()
        sys.exit(1)

    apk = Path(args.apk)

    if args.info:
        cmd_info(apk)
        return

    offset: int | None = None
    if args.offset:
        try:
            offset = int(args.offset, 16)
        except ValueError:
            print(f"[-] Invalid hex offset: {args.offset}")
            sys.exit(1)

    out = Path(args.output) if args.output else None
    success = patch_apk(apk, out, offset)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

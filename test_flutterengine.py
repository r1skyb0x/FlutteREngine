#!/usr/bin/env python3
"""
Comprehensive tests for FlutteREngine.py
=========================================
Covers: elf_arch, load_engine_db, identify_version, _walk_back,
        _find_ssl_offsets_arm64/arm32/x86, find_ssl_offsets,
        dump_dart_offsets, _apply_patch, print_offset_table,
        patch_lib, _build_parser, and the main() CLI entry point.
"""

import csv
import io
import struct
import sys
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch as mock_patch

# Ensure imports resolve from the repo root
sys.path.insert(0, str(Path(__file__).parent))

import FlutteREngine as fe
from FlutteREngine import (
    _apply_patch,
    _build_parser,
    _find_ssl_offsets_arm32,
    _find_ssl_offsets_arm64,
    _find_ssl_offsets_x86,
    _SSL_ERR_PACKED,
    _ARCH_PATCHES,
    _walk_back,
    dump_dart_offsets,
    elf_arch,
    find_ssl_offsets,
    identify_version,
    load_engine_db,
    main,
    patch_lib,
    PATCH_ARM32_THUMB,
    PATCH_ARM32_ARM,
    PATCH_ARM64,
    PATCH_X86,
    print_offset_table,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_elf_header(machine: int, bits: int = 64) -> bytes:
    """Return a minimal 64-byte ELF header with the given machine type."""
    hdr = bytearray(64)
    hdr[0:4] = b'\x7fELF'
    hdr[4] = 2 if bits == 64 else 1   # EI_CLASS
    hdr[5] = 1                          # EI_DATA  (little-endian)
    hdr[6] = 1                          # EI_VERSION
    struct.pack_into('<H', hdr, 18, machine)
    return bytes(hdr)


def _make_arm64_elf(ssl_patterns: bool = False) -> bytes:
    """Minimal ARM64 ELF optionally containing BoringSSL patterns."""
    hdr  = _make_elf_header(183)           # EM_AARCH64
    body = bytearray(0x1000)
    if ssl_patterns:
        # ARM64 prologue STP X29,X30,[SP,#-0x40]!  →  FD 7B BC A9
        body[0x100:0x104] = bytes([0xFD, 0x7B, 0xBC, 0xA9])
        # MOVZ W0, #0x86  →  C0 10 80 52  (within 0x800 of prologue)
        body[0x200:0x204] = bytes([0xC0, 0x10, 0x80, 0x52])
    return hdr + bytes(body)


def _make_arm32_elf(ssl_patterns: bool = False) -> bytes:
    hdr  = _make_elf_header(40, bits=32)   # EM_ARM
    body = bytearray(0x1000)
    if ssl_patterns:
        # Thumb PUSH {r4, LR}  →  2D E9 10 40
        body[0x100:0x104] = bytes([0x2D, 0xE9, 0x10, 0x40])
        body[0x200:0x204] = _SSL_ERR_PACKED
    return hdr + bytes(body)


def _make_x86_elf(ssl_patterns: bool = False) -> bytes:
    hdr  = _make_elf_header(3, bits=32)    # EM_386
    body = bytearray(0x2000)
    if ssl_patterns:
        body[0x100] = 0x55                 # PUSH EBP
        body[0x200:0x204] = _SSL_ERR_PACKED
    return hdr + bytes(body)


def _make_apk(tmp_dir: Path, libs: dict) -> Path:
    """Build a minimal APK (ZIP) containing libflutter.so slice(s)."""
    apk = tmp_dir / "test.apk"
    with zipfile.ZipFile(apk, 'w') as z:
        for abi, data in libs.items():
            z.writestr(f"lib/{abi}/libflutter.so", data)
        z.writestr("AndroidManifest.xml", b"<manifest/>")
    return apk


# ---------------------------------------------------------------------------
# TestElfArch
# ---------------------------------------------------------------------------

class TestElfArch(unittest.TestCase):

    def test_arm64(self):
        self.assertEqual(elf_arch(_make_elf_header(183)), "arm64")

    def test_arm32(self):
        self.assertEqual(elf_arch(_make_elf_header(40, bits=32)), "arm32")

    def test_x86_64(self):
        self.assertEqual(elf_arch(_make_elf_header(62)), "x86_64")

    def test_x86(self):
        self.assertEqual(elf_arch(_make_elf_header(3, bits=32)), "x86")

    def test_too_short(self):
        self.assertEqual(elf_arch(b'\x7fELF\x02'), "unknown")

    def test_empty(self):
        self.assertEqual(elf_arch(b''), "unknown")

    def test_wrong_magic(self):
        data = bytearray(_make_elf_header(183))
        data[0:4] = b'\x00ELF'
        self.assertEqual(elf_arch(bytes(data)), "unknown")

    def test_unknown_machine(self):
        self.assertEqual(elf_arch(_make_elf_header(9999)), "unknown")

    def test_exactly_20_bytes_needed(self):
        """19 bytes → unknown; 20 bytes → valid."""
        hdr = _make_elf_header(183)
        self.assertEqual(elf_arch(hdr[:19]), "unknown")
        self.assertEqual(elf_arch(hdr[:20]), "arm64")


# ---------------------------------------------------------------------------
# TestLoadEngineDb
# ---------------------------------------------------------------------------

class TestLoadEngineDb(unittest.TestCase):

    def test_returns_dict(self):
        self.assertIsInstance(load_engine_db(), dict)

    def test_db_not_empty(self):
        self.assertGreater(len(load_engine_db()), 0)

    def test_keys_are_32hex_snapshot_hashes(self):
        import re
        pat = re.compile(r'^[0-9a-f]{32}$')
        for key in load_engine_db():
            self.assertRegex(key, pat)

    def test_values_have_version_and_commit(self):
        for val in load_engine_db().values():
            self.assertIn('version', val)
            self.assertIn('commit', val)

    def test_missing_csv_returns_empty(self):
        orig = fe.ENGINE_HASH_CSV
        try:
            fe.ENGINE_HASH_CSV = Path("/nonexistent/enginehash.csv")
            self.assertEqual(fe.load_engine_db(), {})
        finally:
            fe.ENGINE_HASH_CSV = orig

    def test_custom_csv_loaded(self):
        orig = fe.ENGINE_HASH_CSV
        try:
            with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.csv', delete=False,
                    newline='', encoding='utf-8') as f:
                w = csv.DictWriter(
                    f, fieldnames=['version', 'Engine_commit', 'Snapshot_Hash'])
                w.writeheader()
                w.writerow({
                    'version':       '9.9.9',
                    'Engine_commit': 'a' * 40,
                    'Snapshot_Hash': 'b' * 32,
                })
                csv_path = Path(f.name)
            fe.ENGINE_HASH_CSV = csv_path
            db = fe.load_engine_db()
            self.assertIn('b' * 32, db)
            self.assertEqual(db['b' * 32]['version'], '9.9.9')
            self.assertEqual(db['b' * 32]['commit'],  'a' * 40)
        finally:
            fe.ENGINE_HASH_CSV = orig
            csv_path.unlink(missing_ok=True)

    def test_row_with_empty_snapshot_hash_skipped(self):
        orig = fe.ENGINE_HASH_CSV
        try:
            with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.csv', delete=False,
                    newline='', encoding='utf-8') as f:
                w = csv.DictWriter(
                    f, fieldnames=['version', 'Engine_commit', 'Snapshot_Hash'])
                w.writeheader()
                # Row with empty Snapshot_Hash
                w.writerow({
                    'version':       '1.0.0',
                    'Engine_commit': 'c' * 40,
                    'Snapshot_Hash': '',
                })
                csv_path = Path(f.name)
            fe.ENGINE_HASH_CSV = csv_path
            db = fe.load_engine_db()
            self.assertEqual(db, {})
        finally:
            fe.ENGINE_HASH_CSV = orig
            csv_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# TestIdentifyVersion
# ---------------------------------------------------------------------------

class TestIdentifyVersion(unittest.TestCase):

    FAKE_DB = {
        'deadbeef' * 4: {'version': '1.2.3', 'commit': 'abc' * 13 + 'a'},
    }

    def test_hash_found(self):
        data   = b'prefix_' + b'deadbeef' * 4 + b'_suffix'
        result = identify_version(data, self.FAKE_DB)
        self.assertIsNotNone(result)
        self.assertEqual(result['version'], '1.2.3')

    def test_hash_not_found(self):
        self.assertIsNone(identify_version(b'no matching hash', self.FAKE_DB))

    def test_empty_data(self):
        self.assertIsNone(identify_version(b'', self.FAKE_DB))

    def test_empty_db(self):
        self.assertIsNone(identify_version(b'deadbeef' * 4, {}))

    def test_hash_embedded_in_binary_noise(self):
        data = bytes(range(128)) + (b'deadbeef' * 4) + bytes(range(128))
        self.assertIsNotNone(identify_version(data, self.FAKE_DB))

    def test_returns_version_from_db(self):
        data = (b'deadbeef' * 4)
        result = identify_version(data, self.FAKE_DB)
        self.assertEqual(result, self.FAKE_DB['deadbeef' * 4])


# ---------------------------------------------------------------------------
# TestWalkBack
# ---------------------------------------------------------------------------

class TestWalkBack(unittest.TestCase):

    import re as _re
    _PAT = __import__('re').compile(b'\xAA')

    def setUp(self):
        import re
        self.pat = re.compile(b'\xAA')

    def test_single_match_found(self):
        data   = b'\x00' * 0x100 + b'\xAA' + b'\x00' * 0x100
        result = _walk_back(data, 0x200, self.pat)
        self.assertEqual(result, [0x100])

    def test_returns_only_nearest_match(self):
        # Two matches; only the one nearest to anchor (last in window) returned
        data   = b'\xAA' + b'\x00' * 0x50 + b'\xAA' + b'\x00' * 0x50
        result = _walk_back(data, 0xB0, self.pat)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], 0x51)

    def test_no_match_returns_empty(self):
        result = _walk_back(b'\x00' * 0x200, 0x100, self.pat)
        self.assertEqual(result, [])

    def test_max_dist_excludes_distant_match(self):
        # Match at offset 0; anchor at 0x900; max_dist=0x800 → window starts at 0x100
        data   = b'\xAA' + b'\x00' * 0x900
        result = _walk_back(data, 0x900, self.pat, max_dist=0x800)
        self.assertEqual(result, [])

    def test_match_within_max_dist(self):
        data   = b'\x00' * 0x100 + b'\xAA' + b'\x00' * 0x700
        result = _walk_back(data, 0x850, self.pat, max_dist=0x800)
        self.assertEqual(result, [0x100])

    def test_anchor_at_start(self):
        result = _walk_back(b'\x00' * 0x100, 0, self.pat)
        self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# TestFindSslOffsetsArm64
# ---------------------------------------------------------------------------

class TestFindSslOffsetsArm64(unittest.TestCase):

    def test_empty_data(self):
        self.assertEqual(_find_ssl_offsets_arm64(b''), [])

    def test_all_zeros(self):
        self.assertEqual(_find_ssl_offsets_arm64(b'\x00' * 0x1000), [])

    def test_movz_0x86_with_prologue(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0xFD, 0x7B, 0xBC, 0xA9])   # prologue
        body[0x200:0x204] = bytes([0xC0, 0x10, 0x80, 0x52])   # MOVZ W0,#0x86
        self.assertIn(0x100, _find_ssl_offsets_arm64(bytes(body)))

    def test_movz_0x14_with_prologue(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0xFD, 0x7B, 0xBD, 0xA9])   # prologue variant
        body[0x200:0x204] = bytes([0x80, 0x02, 0x80, 0x52])   # MOVZ W0,#0x14
        self.assertIn(0x100, _find_ssl_offsets_arm64(bytes(body)))

    def test_ssl_err_packed_with_prologue(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0xFD, 0x7B, 0xBC, 0xA9])
        body[0x200:0x204] = _SSL_ERR_PACKED
        self.assertIn(0x100, _find_ssl_offsets_arm64(bytes(body)))

    def test_unaligned_prologue_not_returned(self):
        body = bytearray(0x1000)
        body[0x101:0x105] = bytes([0xFD, 0x7B, 0xBC, 0xA9])   # offset 0x101 — not 4-aligned
        body[0x200:0x204] = bytes([0xC0, 0x10, 0x80, 0x52])
        self.assertNotIn(0x101, _find_ssl_offsets_arm64(bytes(body)))

    def test_anchor_without_prologue_yields_nothing(self):
        body = bytearray(0x1000)
        body[0x200:0x204] = bytes([0xC0, 0x10, 0x80, 0x52])   # anchor only
        self.assertEqual(_find_ssl_offsets_arm64(bytes(body)), [])

    def test_result_is_sorted(self):
        body = bytearray(0x3000)
        body[0x100:0x104] = bytes([0xFD, 0x7B, 0xBC, 0xA9])
        body[0x200:0x204] = bytes([0xC0, 0x10, 0x80, 0x52])
        body[0x900:0x904] = bytes([0xFD, 0x7B, 0xBD, 0xA9])
        body[0xA00:0xA04] = bytes([0x80, 0x02, 0x80, 0x52])
        result = _find_ssl_offsets_arm64(bytes(body))
        self.assertEqual(result, sorted(result))

    def test_no_duplicate_offsets(self):
        """Multiple anchors pointing to the same prologue → deduplicated."""
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0xFD, 0x7B, 0xBC, 0xA9])
        body[0x200:0x204] = bytes([0xC0, 0x10, 0x80, 0x52])  # anchor 1
        body[0x204:0x208] = bytes([0xC1, 0x10, 0x80, 0x52])  # anchor 2 (W1)
        result = _find_ssl_offsets_arm64(bytes(body))
        self.assertEqual(len(result), len(set(result)))

    def test_all_w0_to_w15_registers_detected(self):
        """MOVZ Wn, #0x86 for n=0..15 should all produce an anchor."""
        for reg in range(16):
            body = bytearray(0x1000)
            body[0x100:0x104] = bytes([0xFD, 0x7B, 0xBC, 0xA9])
            # MOVZ W<reg>, #0x86 → byte0 = 0xC0 | reg
            body[0x200:0x204] = bytes([0xC0 | reg, 0x10, 0x80, 0x52])
            result = _find_ssl_offsets_arm64(bytes(body))
            self.assertIn(0x100, result,
                          f"Register W{reg} not detected as anchor")


# ---------------------------------------------------------------------------
# TestFindSslOffsetsArm32
# ---------------------------------------------------------------------------

class TestFindSslOffsetsArm32(unittest.TestCase):

    def test_empty_data(self):
        self.assertEqual(_find_ssl_offsets_arm32(b''), [])

    def test_all_zeros(self):
        self.assertEqual(_find_ssl_offsets_arm32(b'\x00' * 0x1000), [])

    def test_ssl_err_packed_with_push_lr(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0x2D, 0xE9, 0x10, 0x40])  # PUSH {r4, LR}
        body[0x200:0x204] = _SSL_ERR_PACKED
        self.assertIn(0x100, _find_ssl_offsets_arm32(bytes(body)))

    def test_thumb_movw_0x86_with_push_lr(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0x2D, 0xE9, 0x10, 0x40])
        body[0x200:0x204] = bytes([0x40, 0xF2, 0x86, 0x00])  # MOVW R0, #0x86
        self.assertIn(0x100, _find_ssl_offsets_arm32(bytes(body)))

    def test_anchor_without_prologue_yields_nothing(self):
        body = bytearray(0x1000)
        body[0x200:0x204] = _SSL_ERR_PACKED
        self.assertEqual(_find_ssl_offsets_arm32(bytes(body)), [])

    def test_no_duplicate_offsets(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0x2D, 0xE9, 0x10, 0x40])
        body[0x200:0x204] = _SSL_ERR_PACKED
        body[0x300:0x304] = _SSL_ERR_PACKED       # second anchor, same prologue
        result = _find_ssl_offsets_arm32(bytes(body))
        self.assertEqual(len(result), len(set(result)))

    def test_result_is_sorted(self):
        body = bytearray(0x3000)
        body[0x100:0x104] = bytes([0x2D, 0xE9, 0x10, 0x40])
        body[0x200:0x204] = _SSL_ERR_PACKED
        body[0x900:0x904] = bytes([0x2D, 0xE9, 0x30, 0x40])
        body[0xA00:0xA04] = _SSL_ERR_PACKED
        result = _find_ssl_offsets_arm32(bytes(body))
        self.assertEqual(result, sorted(result))


# ---------------------------------------------------------------------------
# TestFindSslOffsetsX86
# ---------------------------------------------------------------------------

class TestFindSslOffsetsX86(unittest.TestCase):

    def test_empty_data(self):
        self.assertEqual(_find_ssl_offsets_x86(b''), [])

    def test_all_zeros(self):
        self.assertEqual(_find_ssl_offsets_x86(b'\x00' * 0x2000), [])

    def test_ssl_err_packed_with_push_rbp(self):
        body = bytearray(0x2000)
        body[0x100] = 0x55                        # PUSH RBP / PUSH EBP
        body[0x200:0x204] = _SSL_ERR_PACKED
        self.assertIn(0x100, _find_ssl_offsets_x86(bytes(body)))

    def test_imm_0x86_with_push_rbp(self):
        body = bytearray(0x2000)
        body[0x100] = 0x55
        body[0x200:0x204] = bytes([0x86, 0x00, 0x00, 0x00])
        self.assertIn(0x100, _find_ssl_offsets_x86(bytes(body)))

    def test_anchor_without_prologue(self):
        body = bytearray(0x2000)
        body[0x200:0x204] = _SSL_ERR_PACKED
        self.assertEqual(_find_ssl_offsets_x86(bytes(body)), [])

    def test_no_duplicate_offsets(self):
        body = bytearray(0x3000)
        body[0x100] = 0x55
        body[0x200:0x204] = _SSL_ERR_PACKED
        body[0x500:0x504] = _SSL_ERR_PACKED
        result = _find_ssl_offsets_x86(bytes(body))
        self.assertEqual(len(result), len(set(result)))

    def test_max_dist_1000_respected(self):
        """Prologue more than 0x1000 bytes before the anchor should not match."""
        body = bytearray(0x3000)
        body[0x100] = 0x55                        # prologue at 0x100
        body[0x1200:0x1204] = _SSL_ERR_PACKED     # anchor at 0x1200 (distance 0x1100 > 0x1000)
        result = _find_ssl_offsets_x86(bytes(body))
        self.assertNotIn(0x100, result)


# ---------------------------------------------------------------------------
# TestFindSslOffsetsDispatcher
# ---------------------------------------------------------------------------

class TestFindSslOffsetsDispatcher(unittest.TestCase):

    def test_arm64(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0xFD, 0x7B, 0xBC, 0xA9])
        body[0x200:0x204] = bytes([0xC0, 0x10, 0x80, 0x52])
        self.assertIn(0x100, find_ssl_offsets(bytes(body), 'arm64'))

    def test_arm32(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0x2D, 0xE9, 0x10, 0x40])
        body[0x200:0x204] = _SSL_ERR_PACKED
        self.assertIn(0x100, find_ssl_offsets(bytes(body), 'arm32'))

    def test_x86_64(self):
        body = bytearray(0x2000)
        body[0x100] = 0x55
        body[0x200:0x204] = _SSL_ERR_PACKED
        self.assertIn(0x100, find_ssl_offsets(bytes(body), 'x86_64'))

    def test_x86(self):
        body = bytearray(0x2000)
        body[0x100] = 0x55
        body[0x200:0x204] = _SSL_ERR_PACKED
        self.assertIn(0x100, find_ssl_offsets(bytes(body), 'x86'))

    def test_unknown_arch_returns_empty(self):
        self.assertEqual(find_ssl_offsets(b'\x00' * 0x100, 'unknown'), [])

    def test_mips_returns_empty(self):
        self.assertEqual(find_ssl_offsets(b'\x00' * 0x100, 'mips'), [])

    def test_empty_data_all_archs(self):
        for arch in ('arm64', 'arm32', 'x86_64', 'x86'):
            self.assertEqual(find_ssl_offsets(b'', arch), [],
                             f"Expected [] for arch={arch}")


# ---------------------------------------------------------------------------
# TestDumpDartOffsets
# ---------------------------------------------------------------------------

class TestDumpDartOffsets(unittest.TestCase):

    def test_returns_list(self):
        self.assertIsInstance(dump_dart_offsets(b'\x00' * 0x100, 'arm64'), list)

    def test_empty_data(self):
        self.assertIsInstance(dump_dart_offsets(b'', 'arm64'), list)

    def test_each_entry_has_required_keys(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0xFD, 0x7B, 0xBC, 0xA9])
        body[0x200:0x204] = bytes([0xC0, 0x10, 0x80, 0x52])
        for entry in dump_dart_offsets(bytes(body), 'arm64'):
            self.assertIn('name',   entry, f"Missing 'name' in {entry}")
            self.assertIn('offset', entry, f"Missing 'offset' in {entry}")
            self.assertIn('detail', entry, f"Missing 'detail' in {entry}")

    def test_ssl_err_constant_detected(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = _SSL_ERR_PACKED
        result = dump_dart_offsets(bytes(body), 'arm64')
        self.assertTrue(
            any('0x14000086' in e['name'] or 'SSL' in e['name'] for e in result),
            f"SSL error constant not found in {[e['name'] for e in result]}")

    def test_dart_sdk_path_detected(self):
        sdk_str = b'dart-sdk/lib/core/object.dart'
        data    = b'\x00' * 16 + sdk_str + b'\x00'
        result  = dump_dart_offsets(data, 'arm64')
        self.assertTrue(
            any('dart-sdk' in e['name'] or 'dart-sdk' in e['detail']
                for e in result),
            f"dart-sdk path not found in {result}")

    def test_version_string_detected(self):
        data   = b'\x00' * 16 + b'3.27.1' + b'\x00'
        result = dump_dart_offsets(data, 'arm64')
        self.assertTrue(
            any('3.27.1' in e['name'] for e in result),
            f"Version string not found in {[e['name'] for e in result]}")

    def test_results_sorted_by_offset(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0xFD, 0x7B, 0xBC, 0xA9])
        body[0x200:0x204] = bytes([0xC0, 0x10, 0x80, 0x52])
        body[0x300:0x304] = _SSL_ERR_PACKED
        result  = dump_dart_offsets(bytes(body), 'arm64')
        offsets = [e['offset'] for e in result]
        self.assertEqual(offsets, sorted(offsets))

    def test_ssl_candidate_entry_present_when_patterns_found(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0xFD, 0x7B, 0xBC, 0xA9])
        body[0x200:0x204] = bytes([0xC0, 0x10, 0x80, 0x52])
        result = dump_dart_offsets(bytes(body), 'arm64')
        self.assertTrue(
            any('ssl_verify_peer_cert' in e['name'] for e in result),
            "Expected ssl_verify_peer_cert entry when patterns present")


# ---------------------------------------------------------------------------
# TestApplyPatch
# ---------------------------------------------------------------------------

class TestApplyPatch(unittest.TestCase):

    def test_arm64_bytes_written(self):
        buf = bytearray(64)
        self.assertTrue(_apply_patch(buf, 0, 'arm64'))
        self.assertEqual(bytes(buf[:len(PATCH_ARM64)]), PATCH_ARM64)

    def test_arm32_bytes_written(self):
        buf = bytearray(64)
        self.assertTrue(_apply_patch(buf, 0, 'arm32'))
        self.assertEqual(bytes(buf[:len(PATCH_ARM32_THUMB)]), PATCH_ARM32_THUMB)

    def test_x86_64_bytes_written(self):
        buf = bytearray(64)
        self.assertTrue(_apply_patch(buf, 0, 'x86_64'))
        self.assertEqual(bytes(buf[:len(PATCH_X86)]), PATCH_X86)

    def test_x86_bytes_written(self):
        buf = bytearray(64)
        self.assertTrue(_apply_patch(buf, 0, 'x86'))
        self.assertEqual(bytes(buf[:len(PATCH_X86)]), PATCH_X86)

    def test_unknown_arch_returns_false(self):
        buf = bytearray(64)
        self.assertFalse(_apply_patch(buf, 0, 'mips'))

    def test_buffer_too_small_returns_false(self):
        """PATCH_ARM64 is 8 bytes; 4-byte buffer → overflow → False."""
        buf = bytearray(4)
        self.assertFalse(_apply_patch(buf, 0, 'arm64'))

    def test_buffer_unchanged_on_failure(self):
        buf = bytearray(4)
        original = bytes(buf)
        _apply_patch(buf, 0, 'arm64')   # must fail silently
        self.assertEqual(bytes(buf), original)

    def test_non_zero_offset(self):
        buf = bytearray(200)
        off = 50
        self.assertTrue(_apply_patch(buf, off, 'arm64'))
        self.assertEqual(bytes(buf[off:off + len(PATCH_ARM64)]), PATCH_ARM64)

    def test_all_supported_archs_succeed(self):
        for arch in ('arm64', 'arm32', 'x86_64', 'x86'):
            buf = bytearray(200)
            self.assertTrue(_apply_patch(buf, 0, arch),
                            f"_apply_patch returned False for arch={arch}")

    def test_exact_fit_buffer(self):
        """Patch exactly fills the buffer → should succeed."""
        buf = bytearray(len(PATCH_ARM64))
        self.assertTrue(_apply_patch(buf, 0, 'arm64'))

    def test_one_byte_too_small_buffer(self):
        buf = bytearray(len(PATCH_ARM64) - 1)
        self.assertFalse(_apply_patch(buf, 0, 'arm64'))


# ---------------------------------------------------------------------------
# TestArchPatchConstants
# ---------------------------------------------------------------------------

class TestArchPatchConstants(unittest.TestCase):

    def test_arm64_patch_is_movz_ret(self):
        # MOVZ X0, #0 = 00 00 80 D2 ; RET = C0 03 5F D6
        self.assertEqual(PATCH_ARM64,
                         bytes([0x00, 0x00, 0x80, 0xD2,
                                0xC0, 0x03, 0x5F, 0xD6]))

    def test_arm32_thumb_patch_is_movs_bxlr(self):
        # MOVS R0, #0 = 00 20 ; BX LR = 70 47
        self.assertEqual(PATCH_ARM32_THUMB, bytes([0x00, 0x20, 0x70, 0x47]))

    def test_arm32_arm_patch_is_mov_bxlr(self):
        # MOV R0, #0 = 00 00 A0 E3 ; BX LR = 1E FF 2F E1
        self.assertEqual(PATCH_ARM32_ARM,
                         bytes([0x00, 0x00, 0xA0, 0xE3,
                                0x1E, 0xFF, 0x2F, 0xE1]))

    def test_x86_patch_is_xor_ret(self):
        # XOR EAX, EAX = 31 C0 ; RET = C3
        self.assertEqual(PATCH_X86, bytes([0x31, 0xC0, 0xC3]))

    def test_arch_patches_dict_covers_all_archs(self):
        for arch in ('arm64', 'arm32', 'x86_64', 'x86'):
            self.assertIn(arch, _ARCH_PATCHES,
                          f"arch '{arch}' missing from _ARCH_PATCHES")

    def test_ssl_err_packed_value(self):
        # struct.pack('<I', 0x14000086)  →  86 00 00 14
        self.assertEqual(_SSL_ERR_PACKED, bytes([0x86, 0x00, 0x00, 0x14]))


# ---------------------------------------------------------------------------
# TestPrintOffsetTable
# ---------------------------------------------------------------------------

class TestPrintOffsetTable(unittest.TestCase):

    def _capture(self, entries, label="test.so"):
        buf = io.StringIO()
        with mock_patch('sys.stdout', buf):
            print_offset_table(entries, label)
        return buf.getvalue()

    def test_empty_entries_shows_warning(self):
        out = self._capture([])
        self.assertIn("no Dart/BoringSSL offsets found", out)

    def test_entry_offset_shown(self):
        entries = [{"name": "ssl_verify_peer_cert",
                    "offset": 0x1234, "detail": "BoringSSL target"}]
        out = self._capture(entries)
        self.assertIn("0x00001234", out)

    def test_entry_name_shown(self):
        entries = [{"name": "ssl_verify_peer_cert",
                    "offset": 0x10, "detail": "test"}]
        out = self._capture(entries)
        self.assertIn("ssl_verify_peer_cert", out)

    def test_multiple_entries_all_shown(self):
        entries = [
            {"name": "func_a", "offset": 0x100, "detail": "a"},
            {"name": "func_b", "offset": 0x200, "detail": "b"},
        ]
        out = self._capture(entries)
        self.assertIn("func_a", out)
        self.assertIn("func_b", out)

    def test_label_shown_for_non_empty(self):
        entries = [{"name": "x", "offset": 0, "detail": ""}]
        out = self._capture(entries, label="my_lib.so")
        self.assertIn("my_lib.so", out)


# ---------------------------------------------------------------------------
# TestPatchLib
# ---------------------------------------------------------------------------

class TestPatchLib(unittest.TestCase):

    def setUp(self):
        self.tmp     = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_lib(self, data: bytes, name: str = 'libflutter.so') -> Path:
        p = self.tmp_path / name
        p.write_bytes(data)
        return p

    def test_arm64_with_ssl_patterns_patched(self):
        lib = self._write_lib(_make_arm64_elf(ssl_patterns=True))
        patched_offs, msg = patch_lib(lib, 'arm64', None)
        self.assertGreater(len(patched_offs), 0,
                           f"Expected at least one patched offset; msg={msg}")

    def test_arm64_without_ssl_patterns_no_offset(self):
        lib = self._write_lib(_make_arm64_elf(ssl_patterns=False))
        patched_offs, msg = patch_lib(lib, 'arm64', None)
        self.assertEqual(patched_offs, [])
        self.assertIn("not found", msg)

    def test_unknown_arch_no_hint_returns_error(self):
        lib = self._write_lib(b'\x00' * 0x200)  # not a valid ELF
        patched_offs, msg = patch_lib(lib, None, None)
        self.assertEqual(patched_offs, [])
        self.assertIn("Cannot determine", msg)

    def test_manual_offset_overrides_auto_detect(self):
        lib = self._write_lib(_make_arm64_elf())
        # Offset 64 is valid (just past the 64-byte header) with 0x1000-byte body
        patched_offs, msg = patch_lib(lib, 'arm64', 64)
        self.assertIn(64, patched_offs)

    def test_patch_actually_written_to_file(self):
        lib = self._write_lib(_make_arm64_elf(ssl_patterns=True))
        patched_offs, _ = patch_lib(lib, 'arm64', None)
        self.assertGreater(len(patched_offs), 0)
        data = lib.read_bytes()
        for off in patched_offs:
            self.assertEqual(data[off:off + len(PATCH_ARM64)], PATCH_ARM64,
                             f"Patch bytes not found at offset 0x{off:x}")

    def test_arch_hint_from_abi_dir(self):
        """elf_arch returns 'unknown' for non-ELF; hint fills in the gap."""
        # Use a buffer large enough for x86 patch but with no valid ELF header
        lib_data = b'\x00' * 0x300
        lib = self._write_lib(lib_data)
        patched_offs, msg = patch_lib(lib, 'x86', 0x100)
        self.assertIn(0x100, patched_offs)


# ---------------------------------------------------------------------------
# TestBuildParser
# ---------------------------------------------------------------------------

class TestBuildParser(unittest.TestCase):

    def setUp(self):
        self.parser = _build_parser()

    def test_apk_positional_optional(self):
        args = self.parser.parse_args([])
        self.assertIsNone(args.apk)

    def test_apk_positional_captured(self):
        args = self.parser.parse_args(['myapp.apk'])
        self.assertEqual(args.apk, 'myapp.apk')

    def test_output_flag(self):
        args = self.parser.parse_args(['app.apk', '-o', 'out.apk'])
        self.assertEqual(args.output, 'out.apk')

    def test_output_long_flag(self):
        args = self.parser.parse_args(['app.apk', '--output', 'out.apk'])
        self.assertEqual(args.output, 'out.apk')

    def test_offset_flag(self):
        args = self.parser.parse_args(['app.apk', '--offset', '0xdeadbeef'])
        self.assertEqual(args.offset, '0xdeadbeef')

    def test_info_flag(self):
        args = self.parser.parse_args(['--info', 'app.apk'])
        self.assertTrue(args.info)

    def test_dump_offsets_flag(self):
        args = self.parser.parse_args(['--dump-offsets', 'app.apk'])
        self.assertTrue(args.dump_offsets)

    def test_list_versions_flag(self):
        args = self.parser.parse_args(['--list-versions'])
        self.assertTrue(args.list_versions)

    def test_frida_flag(self):
        args = self.parser.parse_args(['--frida', 'app.apk'])
        self.assertTrue(args.frida)

    def test_defaults_are_false_or_none(self):
        args = self.parser.parse_args([])
        self.assertFalse(args.info)
        self.assertFalse(args.dump_offsets)
        self.assertFalse(args.list_versions)
        self.assertFalse(args.frida)
        self.assertIsNone(args.offset)
        self.assertIsNone(args.output)


# ---------------------------------------------------------------------------
# TestCLI (main entry-point integration tests)
# ---------------------------------------------------------------------------

class TestCLI(unittest.TestCase):

    def setUp(self):
        self.tmp      = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_no_args_exits_1(self):
        with self.assertRaises(SystemExit) as cm:
            main([])
        self.assertEqual(cm.exception.code, 1)

    def test_list_versions_no_apk_needed(self):
        try:
            main(['--list-versions'])
        except SystemExit as e:
            self.fail(f"--list-versions raised SystemExit({e.code})")

    def test_nonexistent_apk_exits_1(self):
        with self.assertRaises(SystemExit) as cm:
            main([str(self.tmp_path / 'missing.apk')])
        self.assertEqual(cm.exception.code, 1)

    def test_invalid_hex_offset_exits_1(self):
        apk = _make_apk(self.tmp_path, {'arm64-v8a': _make_arm64_elf()})
        with self.assertRaises(SystemExit) as cm:
            main([str(apk), '--offset', 'not_hex'])
        self.assertEqual(cm.exception.code, 1)

    def test_info_flag_on_valid_apk(self):
        apk = _make_apk(self.tmp_path, {'arm64-v8a': _make_arm64_elf()})
        try:
            main(['--info', str(apk)])
        except SystemExit as e:
            self.fail(f"--info raised SystemExit({e.code})")

    def test_frida_flag_on_valid_apk(self):
        apk = _make_apk(self.tmp_path, {'arm64-v8a': _make_arm64_elf()})
        try:
            main(['--frida', str(apk)])
        except SystemExit as e:
            self.fail(f"--frida raised SystemExit({e.code})")

    def test_dump_offsets_succeeds_even_without_ssl_patterns(self):
        apk = _make_apk(self.tmp_path, {'arm64-v8a': _make_arm64_elf()})
        try:
            main(['--dump-offsets', str(apk)])
        except SystemExit as e:
            self.assertEqual(e.code, 0,
                             f"--dump-offsets exited with code {e.code}")

    def test_dump_offsets_with_ssl_patterns(self):
        apk = _make_apk(self.tmp_path,
                        {'arm64-v8a': _make_arm64_elf(ssl_patterns=True)})
        try:
            main(['--dump-offsets', str(apk)])
        except SystemExit as e:
            self.assertEqual(e.code, 0)

    def test_apk_without_libflutter_exits_nonzero(self):
        """APK with no libflutter.so should fail."""
        apk = self.tmp_path / 'empty.apk'
        with zipfile.ZipFile(apk, 'w') as z:
            z.writestr("assets/dummy.txt", b"hello")
        with self.assertRaises(SystemExit) as cm:
            main([str(apk)])
        self.assertNotEqual(cm.exception.code, 0)

    def test_multiple_abi_slices(self):
        """APK with two ABI slices should be handled without error."""
        apk = _make_apk(self.tmp_path, {
            'arm64-v8a':   _make_arm64_elf(),
            'armeabi-v7a': _make_arm32_elf(),
        })
        try:
            main(['--dump-offsets', str(apk)])
        except SystemExit as e:
            self.assertEqual(e.code, 0)


# ---------------------------------------------------------------------------
# TestPythonVersionCompatibility
# ---------------------------------------------------------------------------

class TestPythonVersionCompatibility(unittest.TestCase):

    def test_running_python_meets_minimum(self):
        self.assertGreaterEqual(
            sys.version_info[:2], (3, 9),
            f"Python 3.9+ required; running {sys.version}")

    def test_version_check_triggers_on_old_python(self):
        """Simulate an old Python version; main() must call sys.exit(1)."""
        with mock_patch('sys.version_info', (3, 8, 0, 'final', 0)):
            with self.assertRaises(SystemExit) as cm:
                main([])
            self.assertEqual(cm.exception.code, 1)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""
Comprehensive tests for patch_flutter.py
==========================================
Covers: elf_arch, load_engine_database, identify_flutter_version,
        _walk_back_to_prologue, find_offsets_arm64/arm32/x86,
        find_offsets dispatcher, apply_patch, patch_libflutter,
        build_parser, and the main() CLI entry point.
"""

import csv
import struct
import sys
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch as mock_patch

sys.path.insert(0, str(Path(__file__).parent))

import patch_flutter as pf
from patch_flutter import (
    _walk_back_to_prologue,
    _SSL_ERR_PACKED,
    apply_patch,
    build_parser,
    elf_arch,
    find_offsets,
    find_offsets_arm32,
    find_offsets_arm64,
    find_offsets_x86,
    identify_flutter_version,
    load_engine_database,
    main,
    patch_libflutter,
    PATCH_ARM32_ARM,
    PATCH_ARM32_THUMB,
    PATCH_ARM64,
    PATCH_X86,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_elf_header(machine: int, bits: int = 64) -> bytes:
    hdr = bytearray(64)
    hdr[0:4] = b'\x7fELF'
    hdr[4] = 2 if bits == 64 else 1
    hdr[5] = 1
    hdr[6] = 1
    struct.pack_into('<H', hdr, 18, machine)
    return bytes(hdr)


def _make_arm64_lib(ssl_patterns: bool = False) -> bytes:
    hdr  = _make_elf_header(183)
    body = bytearray(0x1000)
    if ssl_patterns:
        body[0x100:0x104] = bytes([0xFD, 0x7B, 0xBC, 0xA9])
        body[0x200:0x204] = bytes([0xC0, 0x10, 0x80, 0x52])
    return hdr + bytes(body)


def _make_arm32_lib(ssl_patterns: bool = False) -> bytes:
    hdr  = _make_elf_header(40, bits=32)
    body = bytearray(0x1000)
    if ssl_patterns:
        body[0x100:0x104] = bytes([0x2D, 0xE9, 0x10, 0x40])
        body[0x200:0x204] = _SSL_ERR_PACKED
    return hdr + bytes(body)


def _make_x86_lib(ssl_patterns: bool = False) -> bytes:
    hdr  = _make_elf_header(3, bits=32)
    body = bytearray(0x2000)
    if ssl_patterns:
        body[0x100] = 0x55
        body[0x200:0x204] = _SSL_ERR_PACKED
    return hdr + bytes(body)


def _make_apk(tmp_dir: Path, libs: dict) -> Path:
    apk = tmp_dir / 'test.apk'
    with zipfile.ZipFile(apk, 'w') as z:
        for abi, data in libs.items():
            z.writestr(f'lib/{abi}/libflutter.so', data)
        z.writestr('AndroidManifest.xml', b'<manifest/>')
    return apk


# ---------------------------------------------------------------------------
# TestElfArch
# ---------------------------------------------------------------------------

class TestElfArch(unittest.TestCase):

    def test_arm64(self):
        self.assertEqual(elf_arch(_make_elf_header(183)), 'arm64')

    def test_arm32(self):
        self.assertEqual(elf_arch(_make_elf_header(40, bits=32)), 'arm32')

    def test_x86_64(self):
        self.assertEqual(elf_arch(_make_elf_header(62)), 'x86_64')

    def test_x86(self):
        self.assertEqual(elf_arch(_make_elf_header(3, bits=32)), 'x86')

    def test_empty(self):
        self.assertEqual(elf_arch(b''), 'unknown')

    def test_too_short(self):
        self.assertEqual(elf_arch(b'\x7fELF\x02'), 'unknown')

    def test_bad_magic(self):
        data = bytearray(_make_elf_header(183))
        data[0:4] = b'\x00BAD'
        self.assertEqual(elf_arch(bytes(data)), 'unknown')

    def test_unknown_machine(self):
        self.assertEqual(elf_arch(_make_elf_header(9999)), 'unknown')

    def test_exactly_19_bytes_insufficient(self):
        self.assertEqual(elf_arch(_make_elf_header(183)[:19]), 'unknown')

    def test_exactly_20_bytes_sufficient(self):
        self.assertEqual(elf_arch(_make_elf_header(183)[:20]), 'arm64')


# ---------------------------------------------------------------------------
# TestLoadEngineDatabase
# ---------------------------------------------------------------------------

class TestLoadEngineDatabase(unittest.TestCase):

    def test_returns_dict(self):
        self.assertIsInstance(load_engine_database(), dict)

    def test_not_empty_with_bundled_csv(self):
        self.assertGreater(len(load_engine_database()), 0)

    def test_keys_are_snapshot_hashes(self):
        import re
        pat = re.compile(r'^[0-9a-f]{32}$')
        for key in load_engine_database():
            self.assertRegex(key, pat)

    def test_values_have_version_and_commit(self):
        for val in load_engine_database().values():
            self.assertIn('version', val)
            self.assertIn('commit',  val)

    def test_missing_csv_returns_empty(self):
        orig = pf.ENGINE_HASH_CSV
        try:
            pf.ENGINE_HASH_CSV = Path('/nonexistent/path.csv')
            self.assertEqual(pf.load_engine_database(), {})
        finally:
            pf.ENGINE_HASH_CSV = orig

    def test_custom_csv_read(self):
        orig = pf.ENGINE_HASH_CSV
        try:
            with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.csv', delete=False,
                    newline='', encoding='utf-8') as f:
                w = csv.DictWriter(
                    f, fieldnames=['version', 'Engine_commit', 'Snapshot_Hash'])
                w.writeheader()
                w.writerow({
                    'version':       '7.7.7',
                    'Engine_commit': 'd' * 40,
                    'Snapshot_Hash': 'e' * 32,
                })
                csv_path = Path(f.name)
            pf.ENGINE_HASH_CSV = csv_path
            db = pf.load_engine_database()
            self.assertIn('e' * 32, db)
            self.assertEqual(db['e' * 32]['version'], '7.7.7')
        finally:
            pf.ENGINE_HASH_CSV = orig
            csv_path.unlink(missing_ok=True)

    def test_empty_snapshot_hash_rows_skipped(self):
        orig = pf.ENGINE_HASH_CSV
        try:
            with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.csv', delete=False,
                    newline='', encoding='utf-8') as f:
                w = csv.DictWriter(
                    f, fieldnames=['version', 'Engine_commit', 'Snapshot_Hash'])
                w.writeheader()
                w.writerow({'version': '1.0', 'Engine_commit': 'f' * 40,
                             'Snapshot_Hash': ''})
                csv_path = Path(f.name)
            pf.ENGINE_HASH_CSV = csv_path
            self.assertEqual(pf.load_engine_database(), {})
        finally:
            pf.ENGINE_HASH_CSV = orig
            csv_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# TestIdentifyFlutterVersion
# ---------------------------------------------------------------------------

class TestIdentifyFlutterVersion(unittest.TestCase):

    FAKE_DB = {
        'deadbeef' * 4: {'version': '2.5.0', 'commit': 'aabbcc' * 6 + 'aabb'},
    }

    def test_hash_found(self):
        data   = b'random_' + b'deadbeef' * 4 + b'_data'
        result = identify_flutter_version(data, self.FAKE_DB)
        self.assertIsNotNone(result)
        self.assertEqual(result['version'], '2.5.0')

    def test_hash_not_found_returns_none(self):
        self.assertIsNone(identify_flutter_version(b'no hash here', self.FAKE_DB))

    def test_empty_data(self):
        self.assertIsNone(identify_flutter_version(b'', self.FAKE_DB))

    def test_empty_db(self):
        self.assertIsNone(identify_flutter_version(b'deadbeef' * 4, {}))

    def test_full_return_value(self):
        data   = b'deadbeef' * 4
        result = identify_flutter_version(data, self.FAKE_DB)
        self.assertEqual(result, self.FAKE_DB['deadbeef' * 4])

    def test_hash_embedded_in_binary_noise(self):
        data = bytes(range(256)) + (b'deadbeef' * 4) + bytes(range(256))
        self.assertIsNotNone(identify_flutter_version(data, self.FAKE_DB))


# ---------------------------------------------------------------------------
# TestWalkBackToPrologue
# ---------------------------------------------------------------------------

class TestWalkBackToPrologue(unittest.TestCase):

    def setUp(self):
        import re
        self.prologue_re = re.compile(rb'\xFD\x7B[\xBC-\xBF]\xA9')

    def test_finds_prologue_before_anchor(self):
        data   = b'\x00' * 0x100 + b'\xFD\x7B\xBC\xA9' + b'\x00' * 0x100
        result = _walk_back_to_prologue(data, 0x200, self.prologue_re)
        self.assertEqual(result, [0x100])

    def test_no_prologue_returns_empty(self):
        result = _walk_back_to_prologue(b'\x00' * 0x200, 0x200, self.prologue_re)
        self.assertEqual(result, [])

    def test_returns_nearest_match(self):
        """Two prologues before anchor — only the nearest is returned."""
        data = (b'\xFD\x7B\xBC\xA9' +   # earlier  @ 0x00
                b'\x00' * 0x50 +
                b'\xFD\x7B\xBD\xA9' +   # nearer   @ 0x54
                b'\x00' * 0x50)
        result = _walk_back_to_prologue(data, len(data), self.prologue_re)
        self.assertEqual(result, [0x54])

    def test_max_dist_default_is_0x800(self):
        """Prologue more than 0x800 bytes before anchor must not be found."""
        data   = b'\xFD\x7B\xBC\xA9' + b'\x00' * 0x900
        result = _walk_back_to_prologue(data, 0x904, self.prologue_re)
        self.assertEqual(result, [])

    def test_prologue_within_max_dist(self):
        data   = b'\x00' * 0x100 + b'\xFD\x7B\xBC\xA9' + b'\x00' * 0x600
        result = _walk_back_to_prologue(data, 0x704, self.prologue_re)
        self.assertEqual(result, [0x100])

    def test_custom_max_dist(self):
        data   = b'\x00' * 0x50 + b'\xFD\x7B\xBC\xA9' + b'\x00' * 0x100
        # max_dist=0x40 → anchor-0x40 = 0x94+0x40-0x40 = can't reach 0x50
        # anchor = 0x154; 0x154 - 0x40 = 0x114 → 0x50 not in window
        anchor = 0x50 + 4 + 0x100   # 0x154
        result = _walk_back_to_prologue(data, anchor, self.prologue_re,
                                        max_dist=0x40)
        self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# TestFindOffsetsArm64
# ---------------------------------------------------------------------------

class TestFindOffsetsArm64(unittest.TestCase):

    def test_empty(self):
        self.assertEqual(find_offsets_arm64(b''), [])

    def test_all_zeros(self):
        self.assertEqual(find_offsets_arm64(b'\x00' * 0x1000), [])

    def test_movz_with_prologue(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0xFD, 0x7B, 0xBC, 0xA9])
        body[0x200:0x204] = bytes([0xC0, 0x10, 0x80, 0x52])
        self.assertIn(0x100, find_offsets_arm64(bytes(body)))

    def test_ssl_err_packed_with_prologue(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0xFD, 0x7B, 0xBC, 0xA9])
        body[0x200:0x204] = _SSL_ERR_PACKED
        self.assertIn(0x100, find_offsets_arm64(bytes(body)))

    def test_unaligned_prologue_excluded(self):
        body = bytearray(0x1000)
        body[0x101:0x105] = bytes([0xFD, 0x7B, 0xBC, 0xA9])  # unaligned
        body[0x200:0x204] = bytes([0xC0, 0x10, 0x80, 0x52])
        self.assertNotIn(0x101, find_offsets_arm64(bytes(body)))

    def test_no_duplicate_offsets(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0xFD, 0x7B, 0xBC, 0xA9])
        body[0x200:0x204] = bytes([0xC0, 0x10, 0x80, 0x52])
        body[0x204:0x208] = bytes([0xC2, 0x10, 0x80, 0x52])
        result = find_offsets_arm64(bytes(body))
        self.assertEqual(len(result), len(set(result)))

    def test_result_sorted(self):
        body = bytearray(0x3000)
        body[0x100:0x104] = bytes([0xFD, 0x7B, 0xBC, 0xA9])
        body[0x200:0x204] = bytes([0xC0, 0x10, 0x80, 0x52])
        body[0x900:0x904] = bytes([0xFD, 0x7B, 0xBD, 0xA9])
        body[0xA00:0xA04] = bytes([0x80, 0x02, 0x80, 0x52])
        result = find_offsets_arm64(bytes(body))
        self.assertEqual(result, sorted(result))


# ---------------------------------------------------------------------------
# TestFindOffsetsArm32
# ---------------------------------------------------------------------------

class TestFindOffsetsArm32(unittest.TestCase):

    def test_empty(self):
        self.assertEqual(find_offsets_arm32(b''), [])

    def test_ssl_err_packed_with_push_lr(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0x2D, 0xE9, 0x10, 0x40])
        body[0x200:0x204] = _SSL_ERR_PACKED
        self.assertIn(0x100, find_offsets_arm32(bytes(body)))

    def test_thumb_movw_0x86_with_push_lr(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0x2D, 0xE9, 0x10, 0x40])
        body[0x200:0x204] = bytes([0x40, 0xF2, 0x86, 0x00])
        self.assertIn(0x100, find_offsets_arm32(bytes(body)))

    def test_no_duplicate_offsets(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0x2D, 0xE9, 0x10, 0x40])
        body[0x200:0x204] = _SSL_ERR_PACKED
        body[0x300:0x304] = _SSL_ERR_PACKED
        result = find_offsets_arm32(bytes(body))
        self.assertEqual(len(result), len(set(result)))


# ---------------------------------------------------------------------------
# TestFindOffsetsX86
# ---------------------------------------------------------------------------

class TestFindOffsetsX86(unittest.TestCase):

    def test_empty(self):
        self.assertEqual(find_offsets_x86(b''), [])

    def test_ssl_err_packed_with_push_rbp(self):
        body = bytearray(0x2000)
        body[0x100] = 0x55
        body[0x200:0x204] = _SSL_ERR_PACKED
        self.assertIn(0x100, find_offsets_x86(bytes(body)))

    def test_immediate_0x86_with_push_rbp(self):
        body = bytearray(0x2000)
        body[0x100] = 0x55
        body[0x200:0x204] = bytes([0x86, 0x00, 0x00, 0x00])
        self.assertIn(0x100, find_offsets_x86(bytes(body)))

    def test_no_duplicate_offsets(self):
        body = bytearray(0x3000)
        body[0x100] = 0x55
        body[0x200:0x204] = _SSL_ERR_PACKED
        body[0x500:0x504] = _SSL_ERR_PACKED
        result = find_offsets_x86(bytes(body))
        self.assertEqual(len(result), len(set(result)))


# ---------------------------------------------------------------------------
# TestFindOffsetsDispatcher
# ---------------------------------------------------------------------------

class TestFindOffsetsDispatcher(unittest.TestCase):

    def test_arm64_routed(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0xFD, 0x7B, 0xBC, 0xA9])
        body[0x200:0x204] = bytes([0xC0, 0x10, 0x80, 0x52])
        self.assertIn(0x100, find_offsets(bytes(body), 'arm64'))

    def test_arm32_routed(self):
        body = bytearray(0x1000)
        body[0x100:0x104] = bytes([0x2D, 0xE9, 0x10, 0x40])
        body[0x200:0x204] = _SSL_ERR_PACKED
        self.assertIn(0x100, find_offsets(bytes(body), 'arm32'))

    def test_x86_64_routed(self):
        body = bytearray(0x2000)
        body[0x100] = 0x55
        body[0x200:0x204] = _SSL_ERR_PACKED
        self.assertIn(0x100, find_offsets(bytes(body), 'x86_64'))

    def test_x86_routed(self):
        body = bytearray(0x2000)
        body[0x100] = 0x55
        body[0x200:0x204] = _SSL_ERR_PACKED
        self.assertIn(0x100, find_offsets(bytes(body), 'x86'))

    def test_unknown_returns_empty(self):
        self.assertEqual(find_offsets(b'\x00' * 0x100, 'unknown'), [])

    def test_empty_data_all_archs(self):
        for arch in ('arm64', 'arm32', 'x86_64', 'x86'):
            self.assertEqual(find_offsets(b'', arch), [],
                             f"Expected [] for arch={arch}")


# ---------------------------------------------------------------------------
# TestApplyPatch
# ---------------------------------------------------------------------------

class TestApplyPatch(unittest.TestCase):

    def test_arm64(self):
        buf = bytearray(64)
        self.assertTrue(apply_patch(buf, 0, 'arm64'))
        self.assertEqual(bytes(buf[:len(PATCH_ARM64)]), PATCH_ARM64)

    def test_arm32(self):
        buf = bytearray(64)
        self.assertTrue(apply_patch(buf, 0, 'arm32'))
        self.assertEqual(bytes(buf[:len(PATCH_ARM32_THUMB)]), PATCH_ARM32_THUMB)

    def test_x86_64(self):
        buf = bytearray(64)
        self.assertTrue(apply_patch(buf, 0, 'x86_64'))
        self.assertEqual(bytes(buf[:len(PATCH_X86)]), PATCH_X86)

    def test_x86(self):
        buf = bytearray(64)
        self.assertTrue(apply_patch(buf, 0, 'x86'))
        self.assertEqual(bytes(buf[:len(PATCH_X86)]), PATCH_X86)

    def test_unknown_arch_returns_false(self):
        buf = bytearray(64)
        self.assertFalse(apply_patch(buf, 0, 'mips'))

    def test_buffer_overflow_returns_false(self):
        buf = bytearray(4)           # too small for PATCH_ARM64 (8 bytes)
        self.assertFalse(apply_patch(buf, 0, 'arm64'))

    def test_buffer_unchanged_on_failure(self):
        buf      = bytearray(4)
        original = bytes(buf)
        apply_patch(buf, 0, 'arm64')
        self.assertEqual(bytes(buf), original)

    def test_non_zero_offset(self):
        buf = bytearray(200)
        off = 50
        self.assertTrue(apply_patch(buf, off, 'arm64'))
        self.assertEqual(bytes(buf[off:off + len(PATCH_ARM64)]), PATCH_ARM64)

    def test_all_supported_archs(self):
        for arch in ('arm64', 'arm32', 'x86_64', 'x86'):
            buf = bytearray(200)
            self.assertTrue(apply_patch(buf, 0, arch),
                            f"apply_patch returned False for arch={arch}")

    def test_exact_fit_succeeds(self):
        buf = bytearray(len(PATCH_ARM64))
        self.assertTrue(apply_patch(buf, 0, 'arm64'))

    def test_one_byte_too_small_fails(self):
        buf = bytearray(len(PATCH_ARM64) - 1)
        self.assertFalse(apply_patch(buf, 0, 'arm64'))


# ---------------------------------------------------------------------------
# TestPatchConstants
# ---------------------------------------------------------------------------

class TestPatchConstants(unittest.TestCase):

    def test_arm64_patch_bytes(self):
        self.assertEqual(PATCH_ARM64,
                         bytes([0x00, 0x00, 0x80, 0xD2,
                                0xC0, 0x03, 0x5F, 0xD6]))

    def test_arm32_thumb_patch_bytes(self):
        self.assertEqual(PATCH_ARM32_THUMB, bytes([0x00, 0x20, 0x70, 0x47]))

    def test_arm32_arm_patch_bytes(self):
        self.assertEqual(PATCH_ARM32_ARM,
                         bytes([0x00, 0x00, 0xA0, 0xE3,
                                0x1E, 0xFF, 0x2F, 0xE1]))

    def test_x86_patch_bytes(self):
        self.assertEqual(PATCH_X86, bytes([0x31, 0xC0, 0xC3]))

    def test_ssl_err_packed(self):
        self.assertEqual(_SSL_ERR_PACKED, bytes([0x86, 0x00, 0x00, 0x14]))


# ---------------------------------------------------------------------------
# TestPatchLibflutter
# ---------------------------------------------------------------------------

class TestPatchLibflutter(unittest.TestCase):

    def setUp(self):
        self.tmp      = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, data: bytes, name: str = 'libflutter.so') -> Path:
        p = self.tmp_path / name
        p.write_bytes(data)
        return p

    def test_arm64_with_ssl_patterns_patched(self):
        lib = self._write(_make_arm64_lib(ssl_patterns=True))
        ok, msg = patch_libflutter(lib)
        self.assertTrue(ok, f"Expected success; msg={msg}")

    def test_arm64_without_patterns_fails(self):
        lib = self._write(_make_arm64_lib(ssl_patterns=False))
        ok, msg = patch_libflutter(lib)
        self.assertFalse(ok)
        self.assertTrue(
            "not found" in msg.lower() or "locate" in msg.lower(),
            f"Unexpected failure message: {msg}")

    def test_non_elf_with_no_hint_fails(self):
        lib = self._write(b'\x00' * 0x200)
        ok, msg = patch_libflutter(lib)
        self.assertFalse(ok)
        self.assertIn("Cannot determine", msg)

    def test_manual_offset_used(self):
        lib = self._write(_make_arm64_lib())
        ok, msg = patch_libflutter(lib, manual_offset=64)
        self.assertTrue(ok, f"Expected success; msg={msg}")

    def test_patch_bytes_written_to_file(self):
        lib = self._write(_make_arm64_lib(ssl_patterns=True))
        ok, _  = patch_libflutter(lib)
        self.assertTrue(ok)
        data = lib.read_bytes()
        # Verify patch bytes are present somewhere in the written file
        self.assertIn(PATCH_ARM64, data)

    def test_returns_tuple(self):
        lib    = self._write(_make_arm64_lib())
        result = patch_libflutter(lib, manual_offset=64)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], bool)
        self.assertIsInstance(result[1], str)


# ---------------------------------------------------------------------------
# TestBuildParser
# ---------------------------------------------------------------------------

class TestBuildParser(unittest.TestCase):

    def setUp(self):
        self.parser = build_parser()

    def test_apk_positional_optional(self):
        self.assertIsNone(self.parser.parse_args([]).apk)

    def test_apk_positional_captured(self):
        self.assertEqual(self.parser.parse_args(['app.apk']).apk, 'app.apk')

    def test_output_short_flag(self):
        args = self.parser.parse_args(['app.apk', '-o', 'patched.apk'])
        self.assertEqual(args.output, 'patched.apk')

    def test_output_long_flag(self):
        args = self.parser.parse_args(['app.apk', '--output', 'patched.apk'])
        self.assertEqual(args.output, 'patched.apk')

    def test_offset_flag(self):
        args = self.parser.parse_args(['app.apk', '--offset', '0x1234'])
        self.assertEqual(args.offset, '0x1234')

    def test_info_flag(self):
        self.assertTrue(self.parser.parse_args(['--info', 'app.apk']).info)

    def test_list_versions_flag(self):
        self.assertTrue(
            self.parser.parse_args(['--list-versions']).list_versions)

    def test_default_flags_false_or_none(self):
        args = self.parser.parse_args([])
        self.assertFalse(args.info)
        self.assertFalse(args.list_versions)
        self.assertIsNone(args.offset)
        self.assertIsNone(args.output)


# ---------------------------------------------------------------------------
# TestMain (CLI entry-point)
# ---------------------------------------------------------------------------

class TestMain(unittest.TestCase):

    def setUp(self):
        self.tmp      = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_no_args_exits_1(self):
        with self.assertRaises(SystemExit) as cm:
            main([])
        self.assertEqual(cm.exception.code, 1)

    def test_list_versions_runs_without_error(self):
        try:
            main(['--list-versions'])
        except SystemExit as e:
            self.fail(f"--list-versions raised SystemExit({e.code})")

    def test_nonexistent_apk_exits_1(self):
        with self.assertRaises(SystemExit) as cm:
            main([str(self.tmp_path / 'missing.apk')])
        self.assertEqual(cm.exception.code, 1)

    def test_invalid_hex_offset_exits_1(self):
        apk = _make_apk(self.tmp_path, {'arm64-v8a': _make_arm64_lib()})
        with self.assertRaises(SystemExit) as cm:
            main([str(apk), '--offset', 'ZZZZ'])
        self.assertEqual(cm.exception.code, 1)

    def test_info_on_valid_apk(self):
        apk = _make_apk(self.tmp_path, {'arm64-v8a': _make_arm64_lib()})
        try:
            main(['--info', str(apk)])
        except SystemExit as e:
            self.fail(f"--info raised SystemExit({e.code})")

    def test_apk_without_libflutter_exits_nonzero(self):
        apk = self.tmp_path / 'empty.apk'
        with zipfile.ZipFile(apk, 'w') as z:
            z.writestr('assets/data.txt', b'nothing')
        with self.assertRaises(SystemExit) as cm:
            main([str(apk)])
        self.assertNotEqual(cm.exception.code, 0)


# ---------------------------------------------------------------------------
# TestPythonVersionCompatibility
# ---------------------------------------------------------------------------

class TestPythonVersionCompatibility(unittest.TestCase):

    def test_running_python_meets_minimum(self):
        self.assertGreaterEqual(
            sys.version_info[:2], (3, 9),
            f"Python 3.9+ required; running {sys.version}")

    def test_version_check_triggers_on_old_python(self):
        with mock_patch('sys.version_info', (3, 8, 0, 'final', 0)):
            with self.assertRaises(SystemExit) as cm:
                main([])
            self.assertEqual(cm.exception.code, 1)


if __name__ == '__main__':
    unittest.main()

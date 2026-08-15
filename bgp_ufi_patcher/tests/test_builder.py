#!/usr/bin/env python3

from __future__ import annotations

import struct
import tempfile
import unittest
import zlib
from pathlib import Path


from bgp_ufi_patcher import builder


PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIRMWARE = PROJECT_ROOT / "firmware/ICX7150/Images/SPR09010kufi.bin"


class BuildBgpUfiTests(unittest.TestCase):
    def test_known_shared_spr_hash(self) -> None:
        self.assertIs(
            builder.KNOWN_FIRMWARE[
                "535ed5231be2142e130f7bb3527f3da11cf8ace5e8f95843f951b8eb7ca8ec2a"
            ],
            builder.SPR09010K,
        )

    def test_linx_header_crc_zeros_only_header_crc_field(self) -> None:
        header = bytearray(range(256)) * 2
        struct.pack_into(">I", header, builder.HEADER_CRC_OFFSET, 0xDEADBEEF)
        expected = bytearray(header)
        expected[builder.HEADER_CRC_OFFSET : builder.HEADER_CRC_OFFSET + 4] = b"\0" * 4
        self.assertEqual(builder.linx_header_crc(header), zlib.crc32(expected))

    def test_roundtrip_default_does_not_overwrite_input(self) -> None:
        source = Path("SPR09010kufi.bin")
        self.assertEqual(
            builder.default_roundtrip_path(source), Path("SPR09010kufi-roundtrip.bin")
        )

    def test_bgp_default_does_not_overwrite_input(self) -> None:
        source = Path("firmware/ICX7150/Images/SPR09010kufi.bin")
        self.assertEqual(builder.default_bgp_path(source), Path("SPR09010kufi-bgp.bin"))

    def test_artifact_ids_are_deterministic_sha_prefixes(self) -> None:
        digest = "1c45a6dc953e5ef7d57e45c0ee1c378130e5dc12a85393294bf320877ac030a9"
        self.assertEqual(builder.artifact_id("ufi", digest), "ufi-1c45a6dc953e")
        self.assertEqual(
            builder.artifact_id("clishell-bgp", digest.upper()),
            "clishell-bgp-1c45a6dc953e",
        )
        with self.assertRaises(ValueError):
            builder.artifact_id("bad_kind", digest)
        with self.assertRaises(ValueError):
            builder.artifact_id("ufi", "not-a-sha256")

    def test_embedded_version_is_deterministic_image_sha_prefix(self) -> None:
        first = "1c45a6dc953e5ef7d57e45c0ee1c378130e5dc12a85393294bf320877ac030a9"
        second = "9abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345678"
        self.assertEqual(
            builder.embedded_version_name(builder.SPR09010K, first),
            "SPR09010kB1c45a",
        )
        self.assertEqual(
            builder.embedded_version_name(builder.SPR09010K, first.upper()),
            "SPR09010kB1c45a",
        )
        self.assertEqual(
            builder.embedded_version_name(builder.SPR09010K, second),
            "SPR09010kB9abcd",
        )
        self.assertLess(len("SPR09010kB1c45a"), builder.LINX_NAME_SIZE)
        with self.assertRaises(ValueError):
            builder.embedded_version_name(builder.SPR09010K, "not-a-sha256")

    def test_platform_masks_are_narrow(self) -> None:
        cases = (
            (True, False, 0x04660002),
            (False, True, 0x044E0002),
            (True, True, 0x046E0002),
        )
        for enable_7150, enable_7250, expected in cases:
            with self.subTest(mask=f"0x{expected:08x}"):
                mask = builder.selected_mask(
                    enable_7150=enable_7150, enable_7250=enable_7250
                )
                self.assertEqual(mask, expected)
                self.assertEqual(mask & builder.ICX7150_BASE_L3_PACKAGE, 0)
                self.assertEqual(mask & builder.ICX7250_BASE_L3_PACKAGE, 0)
                self.assertEqual(
                    bool(mask & builder.ICX7150_L3_PACKAGE), enable_7150
                )
                self.assertEqual(
                    bool(mask & builder.ICX7250_L3_PACKAGE), enable_7250
                )

    def test_cli_package_known_offsets(self) -> None:
        self.assertEqual(builder.SPR09010K.cli_package_index, 24)
        self.assertEqual(builder.SPR09010K.cli_package_offset, 0x0482183B)
        self.assertEqual(
            [target.member_name for target in builder.SPR09010K.cli_members],
            [
                "CliShellPkg/bin/fi_cfg_parser",
                "CliShellPkg/bin/fi_cli_shell",
            ],
        )
        self.assertEqual(
            [
                target.artifact.entry_offset(4)
                for target in builder.SPR09010K.cli_members
            ],
            [0x002C2FCD, 0x002BA9C3],
        )

    def test_cli_tar_patches_bgp_selectors(self) -> None:
        if not FIRMWARE.is_file():
            self.skipTest(f"firmware fixture is not available: {FIRMWARE}")
        known = builder.identify_firmware(FIRMWARE)
        layout = builder.parse_layout(FIRMWARE, known)
        original_gzip, original_tar = builder.extract_cli_tar(
            FIRMWARE,
            layout.segment(known.cli_package_index),
        )
        for enable_7150, enable_7250, expected_mask in (
            (True, False, 0x04660002),
            (False, True, 0x044E0002),
            (True, True, 0x046E0002),
        ):
            with self.subTest(mask=f"0x{expected_mask:08x}"):
                patched_tar, artifacts = builder.patch_cli_tar(
                    original_tar,
                    known,
                    enable_7150=enable_7150,
                    enable_7250=enable_7250,
                )
                self.assertEqual(
                    set(artifacts),
                    {"fi_cfg_parser", "fi_cli_shell"},
                )
                self.assertEqual(
                    sum(
                        left != right
                        for left, right in zip(original_tar, patched_tar)
                    ),
                    4,
                )
                rebuilt_gzip = builder.recompress_gzip(
                    original_gzip,
                    patched_tar,
                )
                self.assertEqual(len(rebuilt_gzip), len(original_gzip))
                self.assertEqual(
                    zlib.decompress(rebuilt_gzip, wbits=31),
                    patched_tar,
                )
                for target in known.cli_members:
                    patched = artifacts[target.artifact.name]
                    offsets = {
                        "fi_cfg_parser": (0x2C2FCD, 0x2C2FFD),
                        "fi_cli_shell": (0x2BA9C3, 0x2BA9F3),
                    }[target.artifact.name]
                    expected_entry = expected_mask.to_bytes(4, "big") + b"\0" * 4
                    for offset in offsets:
                        self.assertEqual(patched[offset : offset + 8], expected_entry)

    def test_gzip_rebuild_preserves_header_and_recomputes_trailer(self) -> None:
        source = b"stock tar bytes" * 200
        replacement = source + b" changed"
        compressor = zlib.compressobj(level=6, wbits=-15, memLevel=7)
        prefix = compressor.compress(replacement) + compressor.flush(zlib.Z_SYNC_FLUSH)
        suffix = compressor.flush(zlib.Z_FINISH)
        target_deflate_size = len(prefix) + len(suffix) + 10
        original = (
            bytes.fromhex("1f8b0800785634120003")
            + b"x" * target_deflate_size
            + struct.pack("<II", zlib.crc32(source), len(source))
        )
        rebuilt = builder.recompress_gzip(original, replacement)
        self.assertEqual(rebuilt[:10], original[:10])
        self.assertEqual(len(rebuilt), len(original))
        self.assertEqual(zlib.decompress(rebuilt, wbits=31), replacement)
        self.assertEqual(
            rebuilt[-8:],
            struct.pack("<II", zlib.crc32(replacement), len(replacement)),
        )

    def test_outer_linx_checksum_rewrite(self) -> None:
        header = bytearray(512)
        header[:4] = b"LINX"
        body = b"member index and package data"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "output.bin"
            path.write_bytes(header + body)
            builder.rewrite_outer_header(path, path.stat().st_size)
            rebuilt = path.read_bytes()
        stored_size, header_crc, body_crc = struct.unpack_from(">III", rebuilt, 8)
        normalized = bytearray(rebuilt[:512])
        normalized[builder.HEADER_CRC_OFFSET : builder.HEADER_CRC_OFFSET + 4] = (
            b"\0" * 4
        )
        self.assertEqual(stored_size, len(rebuilt))
        self.assertEqual(header_crc, zlib.crc32(normalized))
        self.assertEqual(body_crc, zlib.crc32(body))

    def test_linx_name_rewrite_is_narrow_and_recomputes_header_crc(self) -> None:
        header = bytearray(512)
        header[:4] = b"LINX"
        header[builder.LINX_NAME_OFFSET : builder.LINX_NAME_OFFSET + 16] = (
            b"SPR09010k".ljust(16, b"\0")
        )
        struct.pack_into(">I", header, builder.BODY_CRC_OFFSET, 0x12345678)
        struct.pack_into(">I", header, builder.HEADER_CRC_OFFSET, 0)
        struct.pack_into(
            ">I",
            header,
            builder.HEADER_CRC_OFFSET,
            builder.linx_header_crc(header),
        )
        original = bytes(header)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.bin"
            path.write_bytes(header)
            builder.rewrite_linx_header_name(
                path,
                0,
                expected_name="SPR09010k",
                replacement_name="SPR09010kB38e7a",
            )
            rebuilt = path.read_bytes()

        self.assertEqual(
            rebuilt[builder.LINX_NAME_OFFSET : builder.LINX_NAME_OFFSET + 16],
            b"SPR09010kB38e7a\0",
        )
        self.assertEqual(
            struct.unpack_from(">I", rebuilt, builder.BODY_CRC_OFFSET)[0],
            0x12345678,
        )
        normalized = bytearray(rebuilt)
        normalized[builder.HEADER_CRC_OFFSET : builder.HEADER_CRC_OFFSET + 4] = (
            b"\0" * 4
        )
        self.assertEqual(
            struct.unpack_from(">I", rebuilt, builder.HEADER_CRC_OFFSET)[0],
            zlib.crc32(normalized),
        )
        allowed = set(range(builder.HEADER_CRC_OFFSET, builder.HEADER_CRC_OFFSET + 4))
        allowed.update(range(builder.LINX_NAME_OFFSET, builder.LINX_NAME_OFFSET + 16))
        self.assertTrue(
            all(
                offset in allowed
                for offset, (left, right) in enumerate(zip(original, rebuilt))
                if left != right
            )
        )


if __name__ == "__main__":
    unittest.main()

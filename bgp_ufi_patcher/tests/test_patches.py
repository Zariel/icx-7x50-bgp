from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path


from bgp_ufi_patcher import patches as patcher


PROJECT_ROOT = Path(__file__).resolve().parents[2]


PARSER = (
    PROJECT_ROOT
    / "extracted/FI09010k/SPR09010k-535ed5231be2/packages"
    / "CliShellPkg/CliShellPkg/CliShellPkg/bin/fi_cfg_parser"
)
SHELL = PARSER.with_name("fi_cli_shell")
FASTIRON = (
    PROJECT_ROOT
    / "extracted/FI09010k/SPR09010k-535ed5231be2/rootfs/FastIron"
)


class PatchFastIronBgpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        for path in (PARSER, SHELL):
            if not path.is_file():
                raise unittest.SkipTest(f"CLI extraction is not available: {path}")

    def test_each_cli_artifact_changes_only_its_documented_byte(self) -> None:
        cases = (
            (PARSER, patcher.PARSER_PATCH),
            (SHELL, patcher.SHELL_PATCH),
        )
        for source, artifact in cases:
            with self.subTest(artifact=artifact.name):
                original = source.read_bytes()
                with tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / f"{artifact.name}-bgp"
                    result = patcher.patch_artifact(source, output)
                    patched = output.read_bytes()

                    self.assertEqual(result.artifact, artifact)
                    self.assertEqual(result.input_sha256, artifact.sha256)
                    self.assertEqual(
                        result.changed_offsets,
                        (artifact.changed_byte_offset,),
                    )
                    self.assertEqual(len(original), len(patched))
                    self.assertEqual(
                        patcher.differing_offsets(original, patched),
                        (artifact.changed_byte_offset,),
                    )
                    self.assertEqual(
                        patched[
                            artifact.selector_entry_offset :
                            artifact.selector_entry_offset
                            + patcher.SELECTOR_ENTRY_SIZE
                        ],
                        patcher.PATCHED_ENTRY,
                    )
                    self.assertEqual(
                        stat.S_IMODE(output.stat().st_mode),
                        stat.S_IMODE(source.stat().st_mode),
                    )

    def test_selector_semantics_admit_7150_and_7250_l3_only(self) -> None:
        self.assertNotEqual(
            patcher.PATCHED_MASK & patcher.ICX7150_L3_PACKAGE,
            0,
        )
        self.assertEqual(
            patcher.PATCHED_MASK & patcher.ICX7150_BASE_L3_PACKAGE,
            0,
        )
        self.assertNotEqual(
            patcher.PATCHED_MASK & patcher.ICX7250_L3_PACKAGE,
            0,
        )
        self.assertEqual(
            patcher.PATCHED_MASK & patcher.ICX7250_BASE_L3_PACKAGE,
            0,
        )

    def test_selective_platform_masks(self) -> None:
        cases = (
            (True, False, 0x04660002),
            (False, True, 0x044E0002),
            (True, True, 0x046E0002),
        )
        for source, artifact in (
            (PARSER, patcher.PARSER_PATCH),
            (SHELL, patcher.SHELL_PATCH),
        ):
            original = source.read_bytes()
            for enable_7150, enable_7250, expected_mask in cases:
                with self.subTest(
                    artifact=artifact.name,
                    mask=f"0x{expected_mask:08x}",
                ):
                    patched, differences = patcher.patch_bytes(
                        original,
                        artifact=artifact,
                        enable_7150=enable_7150,
                        enable_7250=enable_7250,
                    )
                    self.assertEqual(
                        differences,
                        (artifact.changed_byte_offset,),
                    )
                    self.assertEqual(
                        int.from_bytes(
                            patched[
                                artifact.selector_entry_offset :
                                artifact.selector_entry_offset + 4
                            ],
                            "big",
                        ),
                        expected_mask,
                    )

    def test_rejects_empty_platform_selection(self) -> None:
        with self.assertRaisesRegex(patcher.PatchError, "at least one"):
            patcher.patch_bytes(
                PARSER.read_bytes(),
                artifact=patcher.PARSER_PATCH,
                enable_7150=False,
                enable_7250=False,
            )

    def test_rejects_wrong_hash_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bad_input = Path(directory) / "wrong-input"
            output = Path(directory) / "output"
            bad_input.write_bytes(b"not fi_cfg_parser")
            with self.assertRaisesRegex(patcher.PatchError, "not a known"):
                patcher.patch_artifact(bad_input, output)
            self.assertFalse(output.exists())

    def test_rejects_wrong_original_entry(self) -> None:
        original = bytearray(PARSER.read_bytes())
        original[patcher.PARSER_PATCH.changed_byte_offset] ^= 0x01
        with self.assertRaisesRegex(patcher.PatchError, "entry mismatch"):
            patcher.patch_bytes(
                bytes(original),
                artifact=patcher.PARSER_PATCH,
            )

    def test_rejects_fastiron_executable(self) -> None:
        if not FASTIRON.is_file():
            self.skipTest("Task 00 FastIron extraction is missing")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            with self.assertRaisesRegex(patcher.PatchError, "not a known"):
                patcher.patch_artifact(FASTIRON, output)

    def test_refuses_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "existing-output"
            output.write_bytes(b"preserve me")
            with self.assertRaises(patcher.PatchError):
                patcher.patch_artifact(PARSER, output)
            self.assertEqual(output.read_bytes(), b"preserve me")


if __name__ == "__main__":
    unittest.main()

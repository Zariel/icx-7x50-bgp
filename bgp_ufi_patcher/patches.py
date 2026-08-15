"""Admit BGP and IPv6 BGP through selectors 4 and 10 in both CLI executables.

Each eight-byte entry is a big-endian package mask followed by zero runtime
exclusions. Add only the requested licensed L3 package bits, preserving BASE
package rejection. Inputs are recognized by full SHA256; FastIron is unchanged.
See README.md for patch addresses and validation limits.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path


SELECTORS = (4, 10)
SELECTOR_ENTRY_SIZE = 8
ORIGINAL_ENTRY = bytes.fromhex("0446000200000000")
PATCHED_ENTRY = bytes.fromhex("046e000200000000")
ORIGINAL_MASK = 0x04460002
PATCHED_MASK = 0x046E0002
ICX7150_L3_PACKAGE = 0x00200000
ICX7150_BASE_L3_PACKAGE = 0x00100000
ICX7250_L3_PACKAGE = 0x00080000
ICX7250_BASE_L3_PACKAGE = 0x01000000


@dataclass(frozen=True)
class ArtifactPatch:
    name: str
    sha256: str
    size: int
    selector_table_va: int
    selector_table_offset: int

    def entry_offset(self, selector: int) -> int:
        return self.selector_table_offset + selector * SELECTOR_ENTRY_SIZE

    @property
    def changed_offsets(self) -> tuple[int, ...]:
        return tuple(self.entry_offset(selector) + 1 for selector in SELECTORS)


PARSER_PATCH = ArtifactPatch(
    name="fi_cfg_parser",
    sha256="9f0ab954263f76e996da8e08499d5e17152d16768226649a777870cc2ec49824",
    size=4_171_776,
    selector_table_va=0x002CAFAD,
    selector_table_offset=0x002C2FAD,
)

SHELL_PATCH = ArtifactPatch(
    name="fi_cli_shell",
    sha256="5f3839ce95b89779a7798c5f9d30d5d12d49021d89b894954d77522d7408a2ea",
    size=4_136_292,
    selector_table_va=0x002C29A3,
    selector_table_offset=0x002BA9A3,
)

ARTIFACT_PATCHES = (PARSER_PATCH, SHELL_PATCH)
PATCH_BY_SHA256 = {item.sha256: item for item in ARTIFACT_PATCHES}


class PatchError(Exception):
    """The input or requested output is unsafe for this exact patch."""


@dataclass(frozen=True)
class PatchResult:
    artifact: ArtifactPatch
    input_sha256: str
    output_sha256: str
    changed_offsets: tuple[int, ...]
    before: bytes
    after: bytes
    patched_mask: int


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def differing_offsets(before: bytes, after: bytes) -> tuple[int, ...]:
    if len(before) != len(after):
        raise PatchError(
            f"artifact size changed unexpectedly: {len(before)} -> {len(after)}"
        )
    return tuple(
        index for index, pair in enumerate(zip(before, after)) if pair[0] != pair[1]
    )


def validate_elf(data: bytes, artifact: ArtifactPatch) -> None:
    if len(data) != artifact.size:
        raise PatchError(
            f"{artifact.name} size mismatch: expected {artifact.size}, found {len(data)}"
        )
    if len(data) <= artifact.entry_offset(max(SELECTORS)) + SELECTOR_ENTRY_SIZE:
        raise PatchError(f"input is too short: {len(data)} bytes")
    # ELF32, big-endian, version 1, ARM e_machine (0x0028).
    if data[:7] != b"\x7fELF\x01\x02\x01":
        raise PatchError("input is not the expected ELF32 big-endian artifact")
    if data[18:20] != b"\x00\x28":
        raise PatchError("input ELF is not ARM")


def selected_mask(*, enable_7150: bool, enable_7250: bool) -> int:
    if not enable_7150 and not enable_7250:
        raise PatchError("at least one L3 package must be enabled")
    mask = ORIGINAL_MASK
    if enable_7150:
        mask |= ICX7150_L3_PACKAGE
    if enable_7250:
        mask |= ICX7250_L3_PACKAGE
    return mask


def patch_bytes(
    original: bytes,
    *,
    artifact: ArtifactPatch,
    enable_7150: bool = True,
    enable_7250: bool = True,
) -> tuple[bytes, tuple[int, ...]]:
    validate_elf(original, artifact)
    mask = selected_mask(enable_7150=enable_7150, enable_7250=enable_7250)
    patched_entry = mask.to_bytes(4, "big") + b"\0" * 4
    patched = bytearray(original)
    for selector in SELECTORS:
        offset = artifact.entry_offset(selector)
        actual_entry = original[offset : offset + SELECTOR_ENTRY_SIZE]
        if actual_entry != ORIGINAL_ENTRY:
            raise PatchError(
                f"selector-{selector} entry mismatch at 0x{offset:08x}: "
                f"expected {ORIGINAL_ENTRY.hex()}, found {actual_entry.hex()}"
            )
        patched[offset : offset + SELECTOR_ENTRY_SIZE] = patched_entry

    result = bytes(patched)
    differences = differing_offsets(original, result)
    if differences != artifact.changed_offsets:
        formatted = ", ".join(f"0x{offset:08x}" for offset in differences)
        raise PatchError(f"unexpected changed offsets: {formatted or 'none'}")
    return result, differences


def patch_artifact(
    input_path: Path,
    output_path: Path,
    *,
    enable_7150: bool = True,
    enable_7250: bool = True,
) -> PatchResult:
    try:
        if input_path.resolve() == output_path.resolve():
            raise PatchError("input and output must be different paths")
        original = input_path.read_bytes()
    except OSError as error:
        raise PatchError(str(error)) from error

    input_hash = sha256_bytes(original)
    artifact = PATCH_BY_SHA256.get(input_hash)
    if artifact is None:
        raise PatchError(
            "input SHA256 is not a known fi_cfg_parser or fi_cli_shell: "
            f"{input_hash}"
        )

    mask = selected_mask(enable_7150=enable_7150, enable_7250=enable_7250)
    patched, differences = patch_bytes(
        original,
        enable_7150=enable_7150,
        enable_7250=enable_7250,
        artifact=artifact,
    )
    output_hash = sha256_bytes(patched)

    if not output_path.parent.is_dir():
        raise PatchError(f"output directory does not exist: {output_path.parent}")
    try:
        with output_path.open("xb") as stream:
            stream.write(patched)
        input_mode = stat.S_IMODE(input_path.stat().st_mode)
        os.chmod(output_path, input_mode)
    except OSError as error:
        raise PatchError(str(error)) from error

    written = output_path.read_bytes()
    if written != patched:
        raise PatchError("written output does not match the validated patch bytes")

    return PatchResult(
        artifact=artifact,
        input_sha256=input_hash,
        output_sha256=output_hash,
        changed_offsets=differences,
        before=ORIGINAL_ENTRY,
        after=mask.to_bytes(4, "big") + b"\0" * 4,
        patched_mask=mask,
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input",
        type=Path,
        help="stock FI09010k fi_cfg_parser or fi_cli_shell",
    )
    parser.add_argument("output", type=Path, help="new patched output path")
    parser.add_argument("--enable-7150", action="store_true")
    parser.add_argument("--enable-7250", action="store_true")
    return parser.parse_args(argv)


def print_result(result: PatchResult, input_path: Path, output_path: Path) -> None:
    mask = result.patched_mask
    artifact = result.artifact
    icx7150_l3_intersection = mask & ICX7150_L3_PACKAGE
    icx7150_base_intersection = mask & ICX7150_BASE_L3_PACKAGE
    l3_intersection = mask & ICX7250_L3_PACKAGE
    base_intersection = mask & ICX7250_BASE_L3_PACKAGE
    print(f"input: {input_path}")
    print(f"artifact: {artifact.name}")
    print(f"input_sha256: {result.input_sha256}")
    print(f"output: {output_path}")
    print(f"output_sha256: {result.output_sha256}")
    print(f"selector_table_va: 0x{artifact.selector_table_va:08x}")
    for selector in SELECTORS:
        va = artifact.selector_table_va + selector * SELECTOR_ENTRY_SIZE
        print(f"selector_{selector}_va: 0x{va:08x}")
        print(f"selector_{selector}_file_offset: 0x{artifact.entry_offset(selector):08x}")
    print(f"before: {result.before.hex()}")
    print(f"after:  {result.after.hex()}")
    print(
        "changed_offsets: "
        + ", ".join(f"0x{offset:08x}" for offset in result.changed_offsets)
    )
    print(
        "icx7150_l3: "
        f"0x{mask:08x} & 0x{ICX7150_L3_PACKAGE:08x} "
        f"= 0x{icx7150_l3_intersection:08x} "
        f"({'accepted' if icx7150_l3_intersection else 'rejected'})"
    )
    print(
        "icx7150_base_l3: "
        f"0x{mask:08x} & 0x{ICX7150_BASE_L3_PACKAGE:08x} "
        f"= 0x{icx7150_base_intersection:08x} (rejected)"
    )
    print(
        "icx7250_l3: "
        f"0x{mask:08x} & 0x{ICX7250_L3_PACKAGE:08x} "
        f"= 0x{l3_intersection:08x} "
        f"({'accepted' if l3_intersection else 'rejected'})"
    )
    print(
        "icx7250_base_l3: "
        f"0x{mask:08x} & 0x{ICX7250_BASE_L3_PACKAGE:08x} "
        f"= 0x{base_intersection:08x} (rejected)"
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    explicitly_selected = args.enable_7150 or args.enable_7250
    enable_7150 = args.enable_7150 if explicitly_selected else True
    enable_7250 = args.enable_7250 if explicitly_selected else True
    try:
        result = patch_artifact(
            args.input,
            args.output,
            enable_7150=enable_7150,
            enable_7250=enable_7250,
        )
    except PatchError as error:
        print(f"bgp_ufi_patcher.patches: {error}", file=sys.stderr)
        return 1
    print_result(result, args.input, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

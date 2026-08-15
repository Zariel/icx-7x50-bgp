"""Build a bootable UFI containing the narrow BGP package-gate patch.

Only selectors 4 and 10 in ``fi_cfg_parser`` and ``fi_cli_shell`` are changed.  Those
independent gates decide whether configuration parsing and the interactive
CLI admit BGP for the dynamically derived software-package enum.  This does
not alter chassis detection, licence handling, package derivation, FastIron,
the kernel, the FIT, or U-Boot.

FastIron 09.0.10k does not track a per-CliShellPkg revision.  It compares the
global LINX package-set name against the installed ``pkg_ver``.  A patched
build therefore uses ``SPR09010kB<sha5>`` at all three copies of that name,
forcing the normal package reinstall path on first boot.  ``sha5`` comes from
the SHA256 of a checksum-valid canonical build *before* inserting the name;
this avoids an impossible self-referential final-image hash.

The builder fails closed on the complete input hash, expected offsets and
bytes, member lengths, LINX CRCs, preserved non-target members, and read-only
``mkimage`` verification of every FIT payload hash.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import lzma
import os
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import zlib
from dataclasses import dataclass, replace
from pathlib import Path

from .format import (
    CHUNK_SIZE,
    FDT_MAGIC,
    FormatError,
    LINX_HEADER_SIZE,
    LINX_INDEX_OFFSET,
    LinxHeader,
    SIGNATURE_SIZE,
    decompress_one,
    parse_fdt,
    parse_linx_header,
    property_text,
    sha256_bytes,
    sha256_file,
)
from .patches import (
    ArtifactPatch,
    ICX7150_BASE_L3_PACKAGE,
    ICX7150_L3_PACKAGE,
    ICX7250_BASE_L3_PACKAGE,
    ICX7250_L3_PACKAGE,
    ORIGINAL_ENTRY,
    PARSER_PATCH,
    PatchError,
    SHELL_PATCH,
    patch_bytes,
    selected_mask,
)


HEADER_CRC_OFFSET = 0x0C
BODY_CRC_OFFSET = 0x10
LINX_NAME_OFFSET = 0x38
LINX_NAME_SIZE = 0x10
LINX_INDEX_NAME_OFFSET = 2
LINX_INDEX_NAME_SIZE = 0x20
ARTIFACT_ID_HEX_LENGTH = 12
EMBEDDED_VERSION_HASH_LENGTH = 5
EMBEDDED_VERSION_MARKER = "B"


class BuildError(Exception):
    """The input or requested build violates a known-image invariant."""


@dataclass(frozen=True)
class CliMemberPatch:
    member_name: str
    artifact: ArtifactPatch


@dataclass(frozen=True)
class KnownFirmware:
    sha256: str
    size: int
    release: str
    image_name: str
    cli_package_index: int
    cli_package_name: str
    cli_package_offset: int
    cli_package_size: int
    cli_members: tuple[CliMemberPatch, ...]


SPR09010K = KnownFirmware(
    sha256="535ed5231be2142e130f7bb3527f3da11cf8ace5e8f95843f951b8eb7ca8ec2a",
    size=97_090_308,
    release="FI 09.0.10k",
    image_name="SPR09010k",
    cli_package_index=24,
    cli_package_name="CliShellPkg.tar.gz",
    cli_package_offset=0x0482183B,
    cli_package_size=2_561_142,
    cli_members=(
        CliMemberPatch("CliShellPkg/bin/fi_cfg_parser", PARSER_PATCH),
        CliMemberPatch("CliShellPkg/bin/fi_cli_shell", SHELL_PATCH),
    ),
)

KNOWN_FIRMWARE = {SPR09010K.sha256: SPR09010K}


@dataclass(frozen=True)
class Segment:
    index: int
    name: str
    offset: int
    size: int
    kind: str


@dataclass(frozen=True)
class UfiLayout:
    outer: LinxHeader
    segments: tuple[Segment, ...]

    def segment(self, index: int) -> Segment:
        for item in self.segments:
            if item.index == index:
                return item
        raise BuildError(f"missing parsed segment {index}")


@dataclass(frozen=True)
class BuildResult:
    known: KnownFirmware
    output_sha256: str
    output_size: int
    package_sha256: str
    parser_sha256: str
    shell_sha256: str
    selected_mask: int
    embedded_version: str
    version_source_sha256: str
    mkimage_summary: str


def artifact_id(kind: str, sha256: str) -> str:
    """Return a short deterministic display identifier for a built artifact.

    This is deliberately not described as FastIron package-version metadata:
    FI09010k has only a global package-set version and does not compare a
    CliShellPkg-specific revision during boot.
    """

    if not kind or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in kind
    ):
        raise ValueError(f"invalid artifact identifier kind: {kind!r}")
    normalized = sha256.lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(f"invalid SHA256 for artifact identifier: {sha256!r}")
    return f"{kind}-{normalized[:ARTIFACT_ID_HEX_LENGTH]}"


def validate_sha256(sha256: str) -> str:
    normalized = sha256.lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(f"invalid SHA256: {sha256!r}")
    return normalized


def embedded_version_name(known: KnownFirmware, image_sha256: str) -> str:
    """Derive the global package-set name from the canonical rebuilt UFI.

    LINX header names occupy 16 bytes including their NUL terminator.  Keep
    the stock release identity, add an explicit BGP marker, and use the first
    five hexadecimal SHA256 digits (20 bits) of the rebuilt UFI before its
    version fields are changed.  This defined pre-version image avoids a
    circular dependency on the final UFI hash.
    """

    digest = validate_sha256(image_sha256)
    name = (
        f"{known.image_name}{EMBEDDED_VERSION_MARKER}"
        f"{digest[:EMBEDDED_VERSION_HASH_LENGTH]}"
    )
    try:
        encoded = name.encode("ascii")
    except UnicodeEncodeError as error:
        raise BuildError(f"embedded version is not ASCII: {name!r}") from error
    if not encoded or len(encoded) >= LINX_NAME_SIZE:
        raise BuildError(
            f"embedded version {name!r} does not fit the {LINX_NAME_SIZE}-byte "
            "LINX name field"
        )
    return name


def encoded_c_field(value: str, size: int) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise BuildError(f"LINX value is not ASCII: {value!r}") from error
    if not encoded or b"\0" in encoded or len(encoded) >= size:
        raise BuildError(f"LINX value {value!r} does not fit a {size}-byte C field")
    return encoded.ljust(size, b"\0")


def crc32_stream(path: Path, offset: int, size: int) -> int:
    checksum = 0
    with path.open("rb") as stream:
        stream.seek(offset)
        remaining = size
        while remaining:
            chunk = stream.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                raise BuildError(f"truncated input while checksumming at 0x{offset:x}")
            checksum = zlib.crc32(chunk, checksum)
            remaining -= len(chunk)
    return checksum


def linx_header_crc(header: bytes) -> int:
    if len(header) != LINX_HEADER_SIZE:
        raise BuildError(f"LINX header is {len(header)} bytes, expected 512")
    normalized = bytearray(header)
    normalized[HEADER_CRC_OFFSET : HEADER_CRC_OFFSET + 4] = b"\0" * 4
    return zlib.crc32(normalized)


def validate_linx_checksums(path: Path, header: LinxHeader) -> None:
    with path.open("rb") as stream:
        stream.seek(header.offset)
        raw_header = stream.read(LINX_HEADER_SIZE)
    if len(raw_header) != LINX_HEADER_SIZE:
        raise BuildError(f"truncated LINX header at 0x{header.offset:x}")
    stored_header, stored_body = struct.unpack_from(">II", raw_header, HEADER_CRC_OFFSET)
    actual_header = linx_header_crc(raw_header)
    actual_body = crc32_stream(
        path,
        header.offset + LINX_HEADER_SIZE,
        header.total_size - LINX_HEADER_SIZE,
    )
    if stored_header != actual_header:
        raise BuildError(
            f"LINX header CRC mismatch at 0x{header.offset:x}: "
            f"stored 0x{stored_header:08x}, calculated 0x{actual_header:08x}"
        )
    if stored_body != actual_body:
        raise BuildError(
            f"LINX body CRC mismatch at 0x{header.offset:x}: "
            f"stored 0x{stored_body:08x}, calculated 0x{actual_body:08x}"
        )


def identify_firmware(path: Path) -> KnownFirmware:
    try:
        size = path.stat().st_size
        digest = sha256_file(path)
    except OSError as error:
        raise BuildError(str(error)) from error
    known = KNOWN_FIRMWARE.get(digest)
    if known is None:
        raise BuildError(f"unknown firmware SHA256: {digest}")
    if size != known.size:
        raise BuildError(
            f"known firmware size mismatch: expected {known.size}, found {size}"
        )
    return known


def parse_layout(path: Path, known: KnownFirmware) -> UfiLayout:
    try:
        with path.open("rb") as stream:
            outer = parse_linx_header(stream, 0, with_index=True)
            if outer.total_size != known.size:
                raise BuildError(
                    f"outer LINX size {outer.total_size} != known size {known.size}"
                )
            if outer.name != known.image_name:
                raise BuildError(
                    f"outer LINX name {outer.name!r} != {known.image_name!r}"
                )
            if len(outer.entries) <= known.cli_package_index:
                raise BuildError("outer LINX index is shorter than the known layout")

            cursor = outer.data_offset
            segments: list[Segment] = []
            for index, entry in enumerate(outer.entries[:4]):
                if index == 1:
                    segments.append(
                        Segment(index, entry.name, cursor, SIGNATURE_SIZE, "signature")
                    )
                    cursor += SIGNATURE_SIZE
                    continue
                member = parse_linx_header(stream, cursor, with_index=False)
                expected_name = entry.name.removesuffix(".bin")
                if member.name != expected_name:
                    raise BuildError(
                        f"LINX member {index} at 0x{cursor:x} is {member.name!r}, "
                        f"expected {expected_name!r}"
                    )
                segments.append(
                    Segment(index, entry.name, cursor, member.total_size, "linx")
                )
                cursor += member.total_size

            for entry in outer.entries[4:]:
                compressed_size, compression = decompress_one(stream, cursor)
                segments.append(
                    Segment(entry.index, entry.name, cursor, compressed_size, compression)
                )
                cursor += compressed_size
    except (FormatError, OSError, ValueError, zlib.error, lzma.LZMAError) as error:
        raise BuildError(str(error)) from error

    if cursor != known.size:
        raise BuildError(
            f"parsed members end at 0x{cursor:x}, expected 0x{known.size:x}"
        )
    cli = segments[known.cli_package_index]
    expected_cli = (
        known.cli_package_name,
        known.cli_package_offset,
        known.cli_package_size,
    )
    actual_cli = (cli.name, cli.offset, cli.size)
    if actual_cli != expected_cli:
        raise BuildError(
            f"known CliShellPkg layout mismatch: expected {expected_cli}, found {actual_cli}"
        )

    validate_linx_checksums(path, outer)
    for segment in segments:
        if segment.kind == "linx":
            with path.open("rb") as stream:
                member = parse_linx_header(stream, segment.offset, with_index=False)
            validate_linx_checksums(path, member)
    return UfiLayout(outer=outer, segments=tuple(segments))


def copy_range(source, target, offset: int, size: int) -> None:
    source.seek(offset)
    remaining = size
    while remaining:
        chunk = source.read(min(CHUNK_SIZE, remaining))
        if not chunk:
            raise BuildError(f"input changed or truncated at 0x{source.tell():x}")
        target.write(chunk)
        remaining -= len(chunk)


def roundtrip_image(input_path: Path, output_path: Path) -> tuple[KnownFirmware, UfiLayout]:
    known = identify_firmware(input_path)
    layout = parse_layout(input_path, known)
    created_output = False
    try:
        if input_path.resolve() == output_path.resolve():
            raise BuildError("input and output must be different paths")
        if not output_path.parent.is_dir():
            raise BuildError(f"output directory does not exist: {output_path.parent}")
        target = output_path.open("xb")
        created_output = True
        with input_path.open("rb") as source, target:
            copy_range(source, target, 0, layout.outer.data_offset)
            for segment in layout.segments:
                copy_range(source, target, segment.offset, segment.size)
        os.chmod(output_path, stat.S_IMODE(input_path.stat().st_mode))
    except (BuildError, OSError) as error:
        if created_output and output_path.exists():
            output_path.unlink()
        if isinstance(error, BuildError):
            raise
        raise BuildError(str(error)) from error

    output_hash = sha256_file(output_path)
    if output_hash != known.sha256:
        output_path.unlink()
        raise BuildError(
            f"lossless rebuild mismatch: expected {known.sha256}, found {output_hash}"
        )
    return known, layout


def extract_cli_tar(input_path: Path, segment: Segment) -> tuple[bytes, bytes]:
    with input_path.open("rb") as stream:
        stream.seek(segment.offset)
        compressed = stream.read(segment.size)
    if len(compressed) != segment.size:
        raise BuildError("truncated CliShellPkg stream")
    if compressed[:4] != b"\x1f\x8b\x08\x00":
        raise BuildError("CliShellPkg is not the expected flag-free gzip stream")
    try:
        tar_data = zlib.decompress(compressed, wbits=31)
    except zlib.error as error:
        raise BuildError(f"invalid CliShellPkg gzip stream: {error}") from error
    if len(compressed) < 18:
        raise BuildError("truncated CliShellPkg gzip stream")
    stored_crc, stored_size = struct.unpack_from("<II", compressed, len(compressed) - 8)
    if stored_crc != zlib.crc32(tar_data) or stored_size != len(tar_data) & 0xFFFFFFFF:
        raise BuildError("CliShellPkg gzip trailer does not match its tar data")
    return compressed, tar_data


def patch_cli_tar(
    tar_data: bytes,
    known: KnownFirmware,
    *,
    enable_7150: bool,
    enable_7250: bool,
) -> tuple[bytes, dict[str, bytes]]:
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:") as archive:
            members_by_name: dict[str, list[tarfile.TarInfo]] = {}
            for member in archive.getmembers():
                members_by_name.setdefault(member.name, []).append(member)
    except tarfile.TarError as error:
        raise BuildError(f"invalid CliShellPkg tar: {error}") from error

    patched_tar = bytearray(tar_data)
    patched_artifacts: dict[str, bytes] = {}
    expected_tar_offsets: list[int] = []
    for target in known.cli_members:
        matches = members_by_name.get(target.member_name, [])
        if len(matches) != 1 or not matches[0].isfile():
            raise BuildError(f"expected one regular {target.member_name!r} tar member")
        member = matches[0]
        original = tar_data[member.offset_data : member.offset_data + member.size]
        if len(original) != member.size:
            raise BuildError(f"{target.artifact.name} tar member is truncated")
        if sha256_bytes(original) != target.artifact.sha256:
            raise BuildError(
                f"{target.artifact.name} SHA256 does not match the known artifact"
            )
        try:
            patched, differences = patch_bytes(
                original,
                enable_7150=enable_7150,
                enable_7250=enable_7250,
                artifact=target.artifact,
            )
        except PatchError as error:
            raise BuildError(str(error)) from error
        if differences != target.artifact.changed_offsets:
            raise BuildError(
                f"{target.artifact.name} patch is not the expected two-byte change"
            )
        patched_tar[member.offset_data : member.offset_data + member.size] = patched
        patched_artifacts[target.artifact.name] = patched
        expected_tar_offsets.extend(member.offset_data + offset for offset in differences)

    actual_tar_offsets = [
        index
        for index, pair in enumerate(zip(tar_data, patched_tar))
        if pair[0] != pair[1]
    ]
    if actual_tar_offsets != sorted(expected_tar_offsets):
        raise BuildError(
            "CliShellPkg tar changes are not exactly the four selector-4/10 bytes"
        )
    if set(patched_artifacts) != {"fi_cfg_parser", "fi_cli_shell"}:
        raise BuildError("both CLI artifacts were not patched")
    return bytes(patched_tar), patched_artifacts


def recompress_gzip(original: bytes, data: bytes) -> bytes:
    # The known member has a ten-byte, flag-free gzip header. Preserve its
    # timestamp and OS fields. The on-device package reader advances using the
    # stock compressed member length, so keep that framing exact by inserting
    # valid empty DEFLATE stored blocks before the final block.
    if len(original) < 18 or original[:4] != b"\x1f\x8b\x08\x00":
        raise BuildError("unsupported gzip header")
    target_deflate_size = len(original) - 18
    empty_stored_block = b"\x00\x00\x00\xff\xff"
    # Empty stored blocks add five bytes, so a profile must leave a
    # nonnegative deficit divisible by five. Fail closed if none does.
    profiles = ((6, 7), (7, 6), (7, 7), (9, 7), (6, 8), (6, 6))
    compressed: tuple[bytes, bytes, int] | None = None
    for level, memory_level in profiles:
        compressor = zlib.compressobj(
            level=level,
            method=zlib.DEFLATED,
            wbits=-15,
            memLevel=memory_level,
            strategy=zlib.Z_DEFAULT_STRATEGY,
        )
        prefix = compressor.compress(data) + compressor.flush(zlib.Z_SYNC_FLUSH)
        suffix = compressor.flush(zlib.Z_FINISH)
        deficit = target_deflate_size - len(prefix) - len(suffix)
        if deficit >= 0 and deficit % len(empty_stored_block) == 0:
            compressed = prefix, suffix, deficit
            break
    if compressed is None:
        raise BuildError(
            "cannot preserve the known gzip member size with empty DEFLATE blocks: "
            f"target={target_deflate_size}"
        )
    prefix, suffix, deficit = compressed
    deflate = prefix + empty_stored_block * (deficit // 5) + suffix
    trailer = struct.pack("<II", zlib.crc32(data), len(data) & 0xFFFFFFFF)
    rebuilt = original[:10] + deflate + trailer
    try:
        verified = zlib.decompress(rebuilt, wbits=31)
    except zlib.error as error:
        raise BuildError(f"rebuilt gzip failed validation: {error}") from error
    if verified != data:
        raise BuildError("rebuilt gzip does not reproduce patched tar data")
    if len(rebuilt) != len(original):
        raise BuildError("rebuilt gzip did not preserve its indexed member length")
    return rebuilt


def rewrite_linx_header_name(
    output_path: Path,
    header_offset: int,
    *,
    expected_name: str,
    replacement_name: str,
) -> None:
    expected = encoded_c_field(expected_name, LINX_NAME_SIZE)
    replacement = encoded_c_field(replacement_name, LINX_NAME_SIZE)
    with output_path.open("r+b") as stream:
        stream.seek(header_offset)
        raw_header = bytearray(stream.read(LINX_HEADER_SIZE))
        if len(raw_header) != LINX_HEADER_SIZE:
            raise BuildError(f"truncated LINX header at 0x{header_offset:x}")
        if raw_header[:4] != b"LINX":
            raise BuildError(f"missing LINX magic at 0x{header_offset:x}")
        name = bytes(raw_header[LINX_NAME_OFFSET : LINX_NAME_OFFSET + LINX_NAME_SIZE])
        if name != expected:
            raise BuildError(
                f"LINX name at 0x{header_offset + LINX_NAME_OFFSET:x} changed"
            )
        raw_header[LINX_NAME_OFFSET : LINX_NAME_OFFSET + LINX_NAME_SIZE] = replacement
        struct.pack_into(">I", raw_header, HEADER_CRC_OFFSET, 0)
        struct.pack_into(">I", raw_header, HEADER_CRC_OFFSET, linx_header_crc(raw_header))
        stream.seek(header_offset)
        stream.write(raw_header)


def rewrite_runtime_index_name(
    output_path: Path,
    layout: UfiLayout,
    *,
    expected_name: str,
    replacement_name: str,
) -> None:
    if layout.outer.index_entry_size < LINX_INDEX_NAME_OFFSET + LINX_INDEX_NAME_SIZE:
        raise BuildError("outer LINX index entry is too short for its name field")
    expected = encoded_c_field(expected_name, LINX_INDEX_NAME_SIZE)
    replacement = encoded_c_field(replacement_name, LINX_INDEX_NAME_SIZE)
    offset = (
        layout.outer.offset
        + LINX_INDEX_OFFSET
        + LINX_INDEX_NAME_OFFSET
    )
    with output_path.open("r+b") as stream:
        stream.seek(offset)
        current = stream.read(LINX_INDEX_NAME_SIZE)
        if current != expected:
            raise BuildError(f"runtime index name at 0x{offset:x} changed")
        stream.seek(offset)
        stream.write(replacement)


def rewrite_outer_header(output_path: Path, total_size: int) -> None:
    with output_path.open("r+b") as stream:
        raw_header = bytearray(stream.read(LINX_HEADER_SIZE))
        if len(raw_header) != LINX_HEADER_SIZE:
            raise BuildError("rebuilt output has a truncated LINX header")
        struct.pack_into(">I", raw_header, 8, total_size)
        struct.pack_into(">I", raw_header, HEADER_CRC_OFFSET, 0)
        struct.pack_into(">I", raw_header, BODY_CRC_OFFSET, 0)
        stream.seek(0)
        stream.write(raw_header)

    body_crc = crc32_stream(output_path, LINX_HEADER_SIZE, total_size - LINX_HEADER_SIZE)
    struct.pack_into(">I", raw_header, BODY_CRC_OFFSET, body_crc)
    struct.pack_into(">I", raw_header, HEADER_CRC_OFFSET, linx_header_crc(raw_header))
    with output_path.open("r+b") as stream:
        stream.write(raw_header)


def verify_fit_with_mkimage(path: Path, layout: UfiLayout) -> str:
    mkimage = shutil.which("mkimage")
    if mkimage is None:
        raise BuildError("mkimage is required; enter the project Nix dev shell")
    runtime = layout.segment(0)
    fit_offset = runtime.offset + LINX_HEADER_SIZE
    with path.open("rb") as stream:
        stream.seek(fit_offset)
        prefix = stream.read(8)
        if len(prefix) != 8:
            raise BuildError("truncated embedded FIT header")
        magic, fit_size = struct.unpack(">II", prefix)
        if magic != FDT_MAGIC:
            raise BuildError("runtime member does not contain a FIT")
        if fit_size > runtime.size - LINX_HEADER_SIZE:
            raise BuildError("embedded FIT exceeds the runtime LINX member")
        stream.seek(fit_offset)
        fit_blob = stream.read(fit_size)
    if len(fit_blob) != fit_size:
        raise BuildError("truncated embedded FIT")

    # Independently check each ordinary FIT hash. The FIT is preserved, but
    # this makes the build fail closed if the source layout or copy changed.
    root = parse_fdt(fit_blob)
    checked_hashes = 0
    for node in root.child("images").children:
        data_property = node.properties.get("data")
        if data_property is None:
            raise BuildError(f"FIT image {node.path} has no inline data")
        for child in node.children:
            if not child.name.startswith("hash"):
                continue
            algorithm = property_text(child, "algo")
            expected = child.properties.get("value")
            if expected is None:
                raise BuildError(f"FIT hash {child.path} has no value")
            if algorithm == "crc32":
                actual = struct.pack(">I", zlib.crc32(data_property.value))
            elif algorithm == "sha256":
                actual = hashlib.sha256(data_property.value).digest()
            else:
                raise BuildError(f"unsupported FIT hash algorithm {algorithm!r}")
            if actual != expected.value:
                raise BuildError(f"FIT hash mismatch for {node.path}")
            checked_hashes += 1

    with tempfile.NamedTemporaryFile(suffix=".fit") as temporary:
        temporary.write(fit_blob)
        temporary.flush()
        completed = subprocess.run(
            [mkimage, "-l", temporary.name],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    if completed.returncode != 0:
        raise BuildError(f"mkimage rejected preserved FIT:\n{completed.stdout.strip()}")
    description = next(
        (line.strip() for line in completed.stdout.splitlines() if "FIT description" in line),
        "FIT accepted",
    )
    return f"{description}; {checked_hashes} embedded hashes verified"


def compare_bytes_except(
    before: bytes,
    after: bytes,
    allowed_offsets: set[int],
    context: str,
) -> None:
    if len(before) != len(after):
        raise BuildError(f"{context} changed size")
    unexpected = [
        offset
        for offset, (left, right) in enumerate(zip(before, after))
        if left != right and offset not in allowed_offsets
    ]
    if unexpected:
        raise BuildError(f"{context} changed unexpectedly at 0x{unexpected[0]:x}")


def compare_preserved_segments(
    input_path: Path,
    input_layout: UfiLayout,
    output_path: Path,
    output_layout: UfiLayout,
    replaced_index: int,
) -> None:
    with input_path.open("rb") as before, output_path.open("rb") as after:
        before.seek(0)
        after.seek(0)
        compare_bytes_except(
            before.read(LINX_HEADER_SIZE),
            after.read(LINX_HEADER_SIZE),
            set(range(HEADER_CRC_OFFSET, BODY_CRC_OFFSET + 4))
            | set(range(LINX_NAME_OFFSET, LINX_NAME_OFFSET + LINX_NAME_SIZE)),
            "outer LINX header",
        )
        before.seek(LINX_HEADER_SIZE)
        after.seek(LINX_HEADER_SIZE)
        index_size = input_layout.outer.data_offset - LINX_HEADER_SIZE
        compare_bytes_except(
            before.read(index_size),
            after.read(index_size),
            set(
                range(
                    LINX_INDEX_NAME_OFFSET,
                    LINX_INDEX_NAME_OFFSET + LINX_INDEX_NAME_SIZE,
                )
            ),
            "outer LINX member index",
        )
        for source_segment in input_layout.segments:
            if source_segment.index == replaced_index:
                continue
            output_segment = output_layout.segment(source_segment.index)
            if source_segment.size != output_segment.size:
                raise BuildError(f"preserved member {source_segment.name} changed size")
            before.seek(source_segment.offset)
            after.seek(output_segment.offset)
            remaining = source_segment.size
            if source_segment.index == 0:
                compare_bytes_except(
                    before.read(LINX_HEADER_SIZE),
                    after.read(LINX_HEADER_SIZE),
                    set(range(HEADER_CRC_OFFSET, HEADER_CRC_OFFSET + 4))
                    | set(
                        range(
                            LINX_NAME_OFFSET,
                            LINX_NAME_OFFSET + LINX_NAME_SIZE,
                        )
                    ),
                    "runtime LINX header",
                )
                remaining -= LINX_HEADER_SIZE
            while remaining:
                size = min(CHUNK_SIZE, remaining)
                if before.read(size) != after.read(size):
                    raise BuildError(f"preserved member {source_segment.name} changed")
                remaining -= size


def build_patched_image(
    input_path: Path,
    output_path: Path,
    *,
    enable_7150: bool,
    enable_7250: bool,
) -> BuildResult:
    mask = selected_mask(enable_7150=enable_7150, enable_7250=enable_7250)
    known = identify_firmware(input_path)
    layout = parse_layout(input_path, known)
    cli = layout.segment(known.cli_package_index)
    original_gzip, tar_data = extract_cli_tar(input_path, cli)
    patched_tar, patched_artifacts = patch_cli_tar(
        tar_data,
        known,
        enable_7150=enable_7150,
        enable_7250=enable_7250,
    )
    patched_gzip = recompress_gzip(original_gzip, patched_tar)
    package_sha256 = sha256_bytes(patched_gzip)
    output_size = known.size - cli.size + len(patched_gzip)

    created_output = False
    try:
        if input_path.resolve() == output_path.resolve():
            raise BuildError("input and output must be different paths")
        if not output_path.parent.is_dir():
            raise BuildError(f"output directory does not exist: {output_path.parent}")
        target = output_path.open("xb")
        created_output = True
        with input_path.open("rb") as source, target:
            copy_range(source, target, 0, layout.outer.data_offset)
            for segment in layout.segments:
                if segment.index == known.cli_package_index:
                    target.write(patched_gzip)
                else:
                    copy_range(source, target, segment.offset, segment.size)
        if output_path.stat().st_size != output_size:
            raise BuildError("rebuilt UFI size does not match the calculated size")
        # First make a structurally valid image with the stock identity. Its
        # SHA256 is the deterministic, non-circular input to the new identity.
        rewrite_outer_header(output_path, output_size)
        version_source_sha256 = sha256_file(output_path)
        embedded_version = embedded_version_name(known, version_source_sha256)
        rewrite_linx_header_name(
            output_path,
            0,
            expected_name=known.image_name,
            replacement_name=embedded_version,
        )
        rewrite_runtime_index_name(
            output_path,
            layout,
            expected_name=f"{known.image_name}.bin",
            replacement_name=f"{embedded_version}.bin",
        )
        rewrite_linx_header_name(
            output_path,
            layout.segment(0).offset,
            expected_name=known.image_name,
            replacement_name=embedded_version,
        )
        rewrite_outer_header(output_path, output_size)
        os.chmod(output_path, stat.S_IMODE(input_path.stat().st_mode))

        derived = replace(
            known,
            size=output_size,
            image_name=embedded_version,
            cli_package_size=len(patched_gzip),
        )
        output_layout = parse_layout(output_path, derived)
        compare_preserved_segments(
            input_path,
            layout,
            output_path,
            output_layout,
            known.cli_package_index,
        )
        rebuilt_gzip, rebuilt_tar = extract_cli_tar(
            output_path, output_layout.segment(known.cli_package_index)
        )
        if rebuilt_gzip != patched_gzip or rebuilt_tar != patched_tar:
            raise BuildError("rebuilt CliShellPkg differs from the validated package")
        mkimage_summary = verify_fit_with_mkimage(output_path, output_layout)
    except (BuildError, FormatError, OSError, ValueError) as error:
        if created_output and output_path.exists():
            output_path.unlink()
        if isinstance(error, BuildError):
            raise
        raise BuildError(str(error)) from error

    return BuildResult(
        known=known,
        output_sha256=sha256_file(output_path),
        output_size=output_size,
        package_sha256=package_sha256,
        parser_sha256=sha256_bytes(patched_artifacts["fi_cfg_parser"]),
        shell_sha256=sha256_bytes(patched_artifacts["fi_cli_shell"]),
        selected_mask=mask,
        embedded_version=embedded_version,
        version_source_sha256=version_source_sha256,
        mkimage_summary=mkimage_summary,
    )


def default_roundtrip_path(input_path: Path) -> Path:
    return Path(f"{input_path.stem}-roundtrip{input_path.suffix}")


def default_bgp_path(input_path: Path) -> Path:
    return Path(f"{input_path.stem}-bgp{input_path.suffix}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="known stock FastIron UFI image")
    parser.add_argument(
        "--roundtrip",
        action="store_true",
        help="extract/reassemble without a patch and require byte identity",
    )
    parser.add_argument(
        "--enable-7150",
        action="store_true",
        help="admit ICX7150_L3_SOFT_PACKAGE to selectors 4 and 10",
    )
    parser.add_argument(
        "--enable-7250",
        action="store_true",
        help="admit ICX7250_L3_SOFT_PACKAGE to selectors 4 and 10",
    )
    parser.add_argument("--output", type=Path, help="new output path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.roundtrip and (args.enable_7150 or args.enable_7250):
        print(
            "bgp_ufi_patcher: --roundtrip cannot be combined with platform flags",
            file=sys.stderr,
        )
        return 2
    if not args.roundtrip and not (args.enable_7150 or args.enable_7250):
        print(
            "bgp_ufi_patcher: select --enable-7150, --enable-7250, or both",
            file=sys.stderr,
        )
        return 2

    if args.roundtrip:
        output = args.output or default_roundtrip_path(args.input)
        try:
            known, layout = roundtrip_image(args.input, output)
        except BuildError as error:
            print(f"bgp_ufi_patcher: {error}", file=sys.stderr)
            return 1
        print(f"input: {args.input}")
        print(f"input_sha256: {known.sha256}")
        print(f"known_release: {known.release}")
        print(f"parsed_members: {len(layout.segments)}")
        print(f"output: {output}")
        print(f"output_sha256: {sha256_file(output)}")
        print("byte_exact: yes")
        return 0

    output = args.output or default_bgp_path(args.input)
    try:
        result = build_patched_image(
            args.input,
            output,
            enable_7150=args.enable_7150,
            enable_7250=args.enable_7250,
        )
    except BuildError as error:
        print(f"bgp_ufi_patcher: {error}", file=sys.stderr)
        return 1
    print(f"input: {args.input}")
    print(f"input_sha256: {result.known.sha256}")
    print(f"known_release: {result.known.release}")
    print(f"selector_4_and_10_mask: 0x{result.selected_mask:08x}")
    print(f"enable_7150: {'yes' if args.enable_7150 else 'no'}")
    print(f"enable_7250: {'yes' if args.enable_7250 else 'no'}")
    print(f"output: {output}")
    print(f"output_size: {result.output_size}")
    print(f"output_sha256: {result.output_sha256}")
    print(f"ufi_artifact_id: {artifact_id('ufi', result.output_sha256)}")
    print(f"cli_package_sha256: {result.package_sha256}")
    print(
        f"clishellpkg_artifact_id: {artifact_id('clishell-bgp', result.package_sha256)}"
    )
    print(f"fi_cfg_parser_sha256: {result.parser_sha256}")
    print(f"fi_cli_shell_sha256: {result.shell_sha256}")
    print(f"version_source_sha256: {result.version_source_sha256}")
    print(f"embedded_package_version: {result.embedded_version}.bin")
    print(f"mkimage_validation: {result.mkimage_summary}")
    print("runtime_fit_preserved: yes")
    print("runtime_linx_name_versioned: yes")
    print("adjacent_signature_bytes_preserved: yes")
    print("fips_package_manifest_updated: no")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

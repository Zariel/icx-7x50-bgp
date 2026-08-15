"""Minimal parsers for the FI09010k UFI structures used by the patcher.

The image is an outer 512-byte LINX header plus a fixed-size member index.
Its first members are a LINX-wrapped runtime FIT, a 256-byte signature, and
two more LINX images.  The remaining index entries describe concatenated
gzip/XZ package streams; their compressed lengths must be discovered by
walking each stream to its end.

Only CliShellPkg is rebuilt.  The runtime FIT is parsed read-only so every
embedded CRC/SHA hash can be checked, and ``mkimage -l`` provides an
independent FIT-format check.
"""

from __future__ import annotations

import hashlib
import lzma
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO


CHUNK_SIZE = 1024 * 1024
FDT_MAGIC = 0xD00DFEED
LINX_MAGIC = b"LINX"
LINX_HEADER_SIZE = 0x200
LINX_INDEX_OFFSET = 0x200
SIGNATURE_SIZE = 0x100

FDT_BEGIN_NODE = 1
FDT_END_NODE = 2
FDT_PROP = 3
FDT_NOP = 4
FDT_END = 9


class FormatError(ValueError):
    """The input violates a structure observed in the known FI09010k UFI."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_c_string(data: bytes) -> str:
    return data.split(b"\0", 1)[0].decode("ascii", "replace")


def read_exact(stream: BinaryIO, length: int, context: str) -> bytes:
    data = stream.read(length)
    if len(data) != length:
        raise FormatError(f"truncated {context}: wanted {length}, got {len(data)}")
    return data


@dataclass(frozen=True)
class LinxIndexEntry:
    index: int
    flags: int
    name: str


@dataclass(frozen=True)
class LinxHeader:
    offset: int
    total_size: int
    type_bytes: str
    opaque_digest: str
    timestamp: int
    version_bytes: str
    name: str
    index_entry_size: int
    index_entry_count: int
    data_offset: int
    entries: tuple[LinxIndexEntry, ...]


def parse_linx_header(stream: BinaryIO, offset: int, *, with_index: bool) -> LinxHeader:
    stream.seek(offset)
    header = read_exact(stream, LINX_HEADER_SIZE, "LINX header")
    if header[:4] != LINX_MAGIC:
        raise FormatError(f"missing LINX magic at 0x{offset:x}")

    total_size = struct.unpack_from(">I", header, 8)[0]
    if total_size < LINX_HEADER_SIZE:
        raise FormatError(f"invalid LINX size {total_size} at 0x{offset:x}")

    entry_size = struct.unpack_from(">H", header, 0x4E)[0]
    entry_count = struct.unpack_from(">H", header, 0x50)[0]
    entries: list[LinxIndexEntry] = []
    data_offset = offset + LINX_HEADER_SIZE

    if with_index:
        if entry_size < 3 or entry_size > 256:
            raise FormatError(f"implausible LINX index entry size {entry_size}")
        index_length = entry_size * entry_count
        stream.seek(offset + LINX_INDEX_OFFSET)
        raw_index = read_exact(stream, index_length, "LINX member index")
        for index in range(entry_count):
            start = index * entry_size
            flags = struct.unpack_from(">H", raw_index, start)[0]
            name = decode_c_string(raw_index[start + 2 : start + entry_size])
            if not name:
                raise FormatError(f"empty LINX index name at entry {index}")
            entries.append(LinxIndexEntry(index=index, flags=flags, name=name))
        data_offset = offset + LINX_INDEX_OFFSET + index_length

    return LinxHeader(
        offset=offset,
        total_size=total_size,
        type_bytes=header[4:8].hex(),
        opaque_digest=header[0x0C:0x14].hex(),
        timestamp=struct.unpack_from("<I", header, 0x30)[0],
        version_bytes=header[0x34:0x38].hex(),
        name=decode_c_string(header[0x38:0x48]),
        index_entry_size=entry_size,
        index_entry_count=entry_count,
        data_offset=data_offset,
        entries=tuple(entries),
    )


def decompress_one(stream: BinaryIO, offset: int) -> tuple[int, str]:
    """Return a concatenated package stream's exact compressed length."""

    stream.seek(offset)
    magic = stream.read(6)
    stream.seek(offset)
    if magic.startswith(b"\x1f\x8b"):
        decoder = zlib.decompressobj(wbits=31)
        compression = "gzip"
    elif magic == b"\xfd7zXZ\x00":
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        compression = "xz"
    else:
        raise FormatError(f"unknown package compression at 0x{offset:x}: {magic.hex()}")

    consumed = 0
    while not decoder.eof:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            raise FormatError(f"truncated {compression} stream at 0x{offset:x}")
        decoder.decompress(chunk)
        consumed += len(chunk) - len(decoder.unused_data)
    return consumed, compression


def align4(value: int) -> int:
    return (value + 3) & ~3


@dataclass
class FdtProperty:
    value: bytes


@dataclass
class FdtNode:
    name: str
    path: str
    properties: dict[str, FdtProperty] = field(default_factory=dict)
    children: list["FdtNode"] = field(default_factory=list)

    def child(self, name: str) -> "FdtNode":
        for child in self.children:
            if child.name == name:
                return child
        raise FormatError(f"missing FIT node {self.path.rstrip('/')}/{name}")


def parse_fdt(blob: bytes) -> FdtNode:
    """Parse enough flattened-device-tree structure to validate FIT hashes."""

    if len(blob) < 40:
        raise FormatError("truncated FDT header")
    fields = struct.unpack_from(">10I", blob, 0)
    if fields[0] != FDT_MAGIC:
        raise FormatError("missing FDT magic")
    total_size, struct_off, strings_off = fields[1], fields[2], fields[3]
    strings_size, struct_size = fields[8], fields[9]
    if total_size > len(blob):
        raise FormatError(f"FDT total size {total_size} exceeds available {len(blob)}")
    if struct_off + struct_size > total_size or strings_off + strings_size > total_size:
        raise FormatError("FDT structure or strings block lies outside total size")

    strings = blob[strings_off : strings_off + strings_size]
    cursor = struct_off
    structure_end = struct_off + struct_size
    stack: list[FdtNode] = []
    root: FdtNode | None = None

    while cursor + 4 <= structure_end:
        token = struct.unpack_from(">I", blob, cursor)[0]
        cursor += 4
        if token == FDT_BEGIN_NODE:
            nul = blob.find(b"\0", cursor, structure_end)
            if nul < 0:
                raise FormatError("unterminated FDT node name")
            name = blob[cursor:nul].decode("ascii", "replace")
            cursor = align4(nul + 1)
            path = f"{stack[-1].path.rstrip('/')}/{name}" if stack else "/"
            node = FdtNode(name=name, path=path)
            if stack:
                stack[-1].children.append(node)
            elif root is not None:
                raise FormatError("multiple FDT root nodes")
            else:
                root = node
            stack.append(node)
        elif token == FDT_END_NODE:
            if not stack:
                raise FormatError("unbalanced FDT end-node token")
            stack.pop()
        elif token == FDT_PROP:
            if not stack or cursor + 8 > structure_end:
                raise FormatError("invalid FDT property token")
            length, name_offset = struct.unpack_from(">II", blob, cursor)
            cursor += 8
            if cursor + length > structure_end or name_offset >= len(strings):
                raise FormatError("FDT property lies outside its block")
            name_end = strings.find(b"\0", name_offset)
            if name_end < 0:
                raise FormatError("unterminated FDT property name")
            name = strings[name_offset:name_end].decode("ascii", "replace")
            stack[-1].properties[name] = FdtProperty(blob[cursor : cursor + length])
            cursor = align4(cursor + length)
        elif token == FDT_NOP:
            continue
        elif token == FDT_END:
            if stack:
                raise FormatError("unterminated FDT nodes")
            break
        else:
            raise FormatError(f"unknown FDT token 0x{token:x} at 0x{cursor - 4:x}")
    else:
        raise FormatError("missing FDT end token")

    if root is None:
        raise FormatError("missing FDT root node")
    return root


def property_text(node: FdtNode, name: str) -> str:
    prop = node.properties.get(name)
    return decode_c_string(prop.value) if prop else ""

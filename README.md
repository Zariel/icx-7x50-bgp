# FastIron BGP UFI patcher

This repository contains a self-contained Python package that converts the
exact shared FastIron 09.0.10k SPR UFI for ICX7150/7250/7450 into a bootable
image whose BGP command family is admitted on selected ICX7150 and/or ICX7250
L3 software packages. It uses only Python's standard library plus U-Boot's
`mkimage` for final FIT validation.

Original firmware is never modified. Outputs are created exclusively and an
existing output is refused.

## Prerequisites

Before running the patcher, install:

- [uv](https://docs.astral.sh/uv/) for the Python environment (recommended),
  or Python 3.10 or newer
- U-Boot's `mkimage`, usually provided by your operating system's U-Boot tools
  package

## Usage

Download the ICX7250 FastIron 09.0.10k firmware and locate
`SPR09010kufi.bin` in the download. The firmware is not included in this
repository and can be kept anywhere convenient.

The patcher deliberately supports only that exact firmware image. Verify it
before continuing:

```sh
sha256sum /path/to/SPR09010kufi.bin
```

The expected SHA256 is:

```text
535ed5231be2142e130f7bb3527f3da11cf8ace5e8f95843f951b8eb7ca8ec2a
```

Any other firmware version or build is rejected without producing an output.

Then run the patcher from this repository's root. `uv` creates the project
environment, obtains a compatible Python when needed, and exposes the
`bgp-ufi-patcher` command. The input may be an absolute or relative path:

```sh
# Prove parsing/reassembly is byte-exact without patching.
uv run bgp-ufi-patcher /path/to/SPR09010kufi.bin --roundtrip

# Enable one platform.
uv run bgp-ufi-patcher /path/to/SPR09010kufi.bin --enable-7150
uv run bgp-ufi-patcher /path/to/SPR09010kufi.bin --enable-7250

# Enable both in the same shared image.
uv run bgp-ufi-patcher /path/to/SPR09010kufi.bin \
  --enable-7150 --enable-7250
```

With the input shown above, the patcher creates `SPR09010kufi-bgp.bin` in the
directory from which it was run. That image can then be flashed onto an
ICX7150 or ICX7250 using the usual firmware update procedure, according to the
platform option or options selected when it was built. Use `--output PATH` to
choose a different new output path. The command prints the input, output,
package, and patched-ELF SHA256 values along with the embedded version and FIT
validation result.

There are no third-party Python dependencies, so uv is optional. With Python
3.10 or newer and `mkimage` already installed, run directly from the repository
root instead:

```sh
python3 -m bgp_ufi_patcher /path/to/SPR09010kufi.bin --enable-7250
```

Run the tests through the same project environment:

```sh
uv run python -m unittest discover -s bgp_ufi_patcher/tests -v
```

## What enables BGP

FastIron derives a one-bit software-package enum on demand from chassis-family
and per-unit licence state. Two CLI front ends independently test that enum
against selector 4's supported-package mask:

| Binary | Role | Selector-4 file offset | Selector-4 VA |
|---|---|---:|---:|
| `fi_cfg_parser` | saved configuration parsing | `0x002c2fcd` | `0x002cafcd` |
| `fi_cli_shell` | interactive CLI validation | `0x002ba9c3` | `0x002c29c3` |

The stock eight-byte entry is a big-endian mask followed by zero:

```text
04 46 00 02 00 00 00 00    0x04460002
```

The builder adds only the selected L3 bits and writes the same mask to both
ELFs:

```text
ICX7150 L3 bit: 0x00200000   -> mask 0x04660002
ICX7250 L3 bit: 0x00080000   -> mask 0x044e0002
both:                         -> mask 0x046e0002
```

Each ELF therefore changes at exactly one byte. ICX7150 BASE L3
(`0x00100000`) and ICX7250 BASE L3 (`0x01000000`) remain absent. The patch does
not alter chassis identity, licence handling, software-package derivation,
the generic selector predicate, individual CLI nodes, `FastIron`, the kernel,
the FIT, or U-Boot. Hardware testing established that the parser-only patch
was insufficient; both copies are required, and the two-gate image admits BGP
on an ICX7150.

## Licence selection versus feature policy

The L3 licence does not turn on a single mutable capability profile. FastIron
first combines detected chassis family with the local stack unit's numeric L3
licence state. The per-unit selector at FastIron VA `0x006ba800` calls the
licence getter at `0x006be7d0`; zero selects the model's BASE enum and nonzero
selects its L3 enum:

| Model | Family mask | Licence absent: BASE enum | L3 licence present: L3 enum |
|---|---:|---:|---:|
| ICX7450 | `0x00100000` | `0x02000000` | `0x00040000` |
| ICX7250 | `0x00200000` | `0x01000000` | `0x00080000` |

Names such as `l3-prem` and `l3-prem-8X10G` are licence input/display names;
they are not package objects. For package selection, the observed decision is
zero versus nonzero. The resulting one-hot enum is then intersected with each
CLI feature family's selector mask. Licence selection and feature policy are
therefore separate stages:

```text
chassis family + per-unit L3 licence
  -> model-specific BASE or L3 package enum
  -> feature selector's package mask
  -> admit or hide that CLI family
```

The stock package gates compare as follows:

| Feature family | Selector(s) | Stock mask | 7450 BASE | 7450 L3 | 7250 BASE | 7250 L3 |
|---|---:|---:|---:|---:|---:|---:|
| BGP/BGP4+ | 4 | `0x04460002` | no | yes | no | **no** |
| OSPF/OSPFv3 | 3 | `0x046e0002` | no | yes | no | yes |
| IPv4 PIM/MSDP | 5 | `0x046e0002` | no | yes | no | yes |
| PBR contexts | 8, 14 | `0x046e0002` | no | yes | no | yes |
| RIP/RIPng | 2 | `0x0ffe0006` | yes | yes | yes | yes |
| IPv6 PIM-Sparse | 6 | `0x0ffe0006` | yes | yes | yes | yes |

This table describes the package-selector result. A command can have an
additional runtime-state flag: MSDP is the observed example. The top-level
OSPF and BGP nodes do not. After selector admission, their CLI-to-IPC paths
are structurally parallel and no later package, chassis, or licence check was
found.

The key contrast is that a licensed ICX7250 already derives
`ICX7250_L3_SOFT_PACKAGE` and passes OSPF, PIM, and PBR masks. Stock BGP still
rejects it because selector 4 contains the licensed ICX7450 bit
`0x00040000`, but not the licensed ICX7250 bit `0x00080000`. The patch changes
only that feature policy. For a 7250-enabled build, selector 4 becomes
`0x044e0002`; the BASE enum remains excluded, so the L3 licence is still
required. A combined 7150/7250 build uses `0x046e0002`, matching the existing
OSPF/PIM/PBR package coverage without changing how any licence is obtained or
interpreted.

## Firmware format

The observed SPR09010k UFI is a LINX container:

```text
outer LINX header (0x200 bytes)
outer member index (50 records x 42 bytes; data starts at 0x0a34)
├── runtime LINX member
│   └── FIT: kernel, ramdisk/rootfs, device tree, hashes/configuration
├── adjacent opaque 0x100-byte signature
├── two further LINX-wrapped boot images
└── concatenated gzip/XZ package members
    └── member 24: CliShellPkg.tar.gz
```

Index records contain flags, a NUL-padded name, relative offset, and compressed
size. Package streams are nevertheless walked to decompressor EOF and checked
against the known layout. `CliShellPkg.tar.gz` is at absolute offset
`0x0482183b` and is `2,561,142` bytes in the stock image.

The builder edits the two ELF bytes in the package's uncompressed tar, then
recomputes the gzip CRC32/size trailer. The package reader relies on stock
member framing, so the compressor pads with valid empty DEFLATE stored blocks
to retain the exact compressed length. This is a known-image technique, not a
general UFI writer.

The runtime FIT and adjacent signature are copied byte-for-byte. The builder
recomputes affected LINX header/body CRC32 fields, checks every non-target
member for equality, independently verifies all inline FIT CRC32/SHA256
properties, and requires `mkimage -l` to accept the preserved FIT.

## Deterministic reinstall version

FI 09.0.10k has no per-`CliShellPkg` revision or checksum comparison. At boot,
`process_packages` derives three global names from LINX runtime headers:

```text
booted runtime image name
UFI runtime image name
installed /.pkg/pkg_ver.bin name
```

It compares the names for equality with `strncmp(..., 32)`. An unchanged
`SPR09010k.bin` therefore causes the installer to skip the modified package.
The patcher gives every payload-distinct build a deterministic global name:

```text
SPR09010kB<sha5>.bin
```

`sha5` is the first five hexadecimal digits (20 bits) of a complete,
checksum-valid canonical UFI containing the requested patch while its LINX
names still have the stock identity. Hashing this defined pre-version image
avoids a circular requirement for the final image to contain a prefix of its
own hash. The derived name is written to:

```text
outer LINX header name       file 0x00000038
outer index runtime name     file 0x00000202
runtime LINX header name     file 0x00000a6c
```

The associated LINX CRCs are recomputed. Matching the booted and UFI names
passes the compatibility check; differing from the old installed `pkg_ver`
selects FastIron's normal package installation path. After installation, the
new runtime header becomes `/.pkg/pkg_ver.bin`, so later boots skip it.

Consequences and limits:

- The name change causes the complete UFI package set to reinstall on first
  boot, even though only `CliShellPkg` payload bytes changed. There is no
  selective package-version primitive in this release.
- Five hex digits fit the 16-byte LINX name field and give only a 20-bit
  identifier. A prefix collision is possible; the tool always prints full
  SHA256 values for unambiguous artifact tracking.
- The stock rootfs FIPS package manifest is not rewritten. Do not use a
  patched image with `fips_enabled`.
- Only the exact known SPR image and exact known CLI ELF hashes are supported.
  Layout drift or already-patched inputs fail closed.
- Keep a known-good primary image and configuration recovery path. The tool
  creates a structurally verified image; it does not make firmware testing
  risk-free or establish unsupported routing scale limits.

Implementation is split into `builder.py` (container rebuild and validation),
`patches.py` (the two selector records), and `format.py` (minimal LINX/FIT
parsing). No module imports the broader research tooling outside this
repository.

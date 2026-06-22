#!/usr/bin/env python3
"""Re-align the Mach-O symbol string table to an 8-byte boundary.

Why this exists: the arm64e dylib produced by `cargo build -Z build-std` with the
Apple `ld-1328.2` linker (Xcode 26 / mid-2026) places the LC_SYMTAB string table at a
4-byte-aligned file offset. macOS 26/Tahoe's dyld requires 8-byte alignment for the
string pool and refuses to map the image ("mis-aligned LINKEDIT string pool"), so the
module cannot load into sudo/su. See CLAUDE.md "arm64e LINKEDIT alignment workaround".

What it does: inserts the minimum number of zero bytes (0..7) before the string table
so its file offset is a multiple of 8, then fixes every load-command offset that points
at/after the insertion point and grows the __LINKEDIT segment. It touches no code, only
LINKEDIT layout. It is idempotent (a no-op when already 8-aligned) and arch-agnostic
(safe on the host arm64 build too, where it is typically a no-op).

The binary must be (re)signed afterwards: the caller runs `codesign` so the signature
covers the realigned file. Verify success by loading it in an arm64e process (the
dlopen probe is a perfect oracle) and with `codesign --verify --strict`.

Usage: realign-linkedit.py <path-to-thin-macho-dylib>
"""

import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF

LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_SEGMENT_64 = 0x19
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
# linkedit_data_command kinds (cmd, cmdsize, dataoff, datasize)
LINKEDIT_DATA_CMDS = {
    0x1D,  # LC_CODE_SIGNATURE
    0x1E,  # LC_SEGMENT_SPLIT_INFO
    0x26,  # LC_FUNCTION_STARTS
    0x29,  # LC_DATA_IN_CODE
    0x2B,  # LC_DYLIB_CODE_SIGN_DRS
    0x2E,  # LC_LINKER_OPTIMIZATION_HINT
    0x80000033,  # LC_DYLD_EXPORTS_TRIE
    0x80000034,  # LC_DYLD_CHAINED_FIXUPS
}


def fail(msg):
    sys.exit(f"realign-linkedit: {msg}")


def main():
    if len(sys.argv) != 2:
        fail("usage: realign-linkedit.py <dylib>")
    path = sys.argv[1]
    with open(path, "rb") as f:
        data = bytearray(f.read())

    if len(data) < 32:
        fail("file too small to be a Mach-O")
    (magic,) = struct.unpack_from("<I", data, 0)
    if magic in (FAT_MAGIC, FAT_MAGIC_64) or magic in (0xBEBAFECA, 0xBFBAFECA):
        fail("fat/universal binaries are not supported; pass a thin Mach-O")
    if magic != MH_MAGIC_64:
        fail(f"not a little-endian 64-bit Mach-O (magic={magic:#010x})")

    (ncmds,) = struct.unpack_from("<I", data, 16)

    # Pass 1: find the original string-table offset.
    off = 32
    stroff = None
    cmd_locs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize < 8 or off + cmdsize > len(data):
            fail(f"corrupt load command at {off:#x}")
        cmd_locs.append((cmd, off))
        if cmd == LC_SYMTAB:
            (_symoff, _nsyms, stroff, _strsize) = struct.unpack_from("<IIII", data, off + 8)
        off += cmdsize
    if stroff is None:
        fail("no LC_SYMTAB found")

    pad = (8 - (stroff % 8)) % 8
    if pad == 0:
        print(f"realign-linkedit: string table already 8-aligned (stroff={stroff}); no change")
        return

    print(f"realign-linkedit: stroff={stroff} mis-aligned; inserting {pad} byte(s) -> {stroff + pad}")

    # Insert zero padding immediately before the string table.
    data[stroff:stroff] = b"\x00" * pad

    # Pass 2: bump every file offset that points at/after the insertion point. Anything
    # strictly before `stroff` is untouched; the string table (== stroff) and anything
    # after it (e.g. a code signature) move by `pad`.
    for cmd, o in cmd_locs:
        if cmd == LC_SYMTAB:
            symoff, nsyms, st, strsize = struct.unpack_from("<IIII", data, o + 8)
            if symoff > stroff:
                symoff += pad
            st += pad  # the string table itself
            struct.pack_into("<IIII", data, o + 8, symoff, nsyms, st, strsize)
        elif cmd == LC_DYSYMTAB:
            fields = list(struct.unpack_from("<" + "I" * 18, data, o + 8))
            for i in (6, 8, 10, 12, 14, 16):  # tocoff, modtaboff, extrefsymoff, indirectsymoff, extreloff, locreloff
                if fields[i] != 0 and fields[i] > stroff:
                    fields[i] += pad
            struct.pack_into("<" + "I" * 18, data, o + 8, *fields)
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            fields = list(struct.unpack_from("<" + "I" * 10, data, o + 8))
            for i in (0, 2, 4, 6, 8):  # rebase_off, bind_off, weak_bind_off, lazy_bind_off, export_off
                if fields[i] != 0 and fields[i] > stroff:
                    fields[i] += pad
            struct.pack_into("<" + "I" * 10, data, o + 8, *fields)
        elif cmd in LINKEDIT_DATA_CMDS:
            dataoff, datasize = struct.unpack_from("<II", data, o + 8)
            if dataoff != 0 and dataoff > stroff:
                struct.pack_into("<II", data, o + 8, dataoff + pad, datasize)
        elif cmd == LC_SEGMENT_64:
            segname = bytes(data[o + 8:o + 24]).split(b"\x00")[0]
            if segname == b"__LINKEDIT":
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, o + 24)
                if not (fileoff <= stroff <= fileoff + filesize):
                    fail("string table is not inside __LINKEDIT; refusing to patch")
                filesize += pad
                if vmsize < filesize:
                    page = 0x4000
                    vmsize = (filesize + page - 1) & ~(page - 1)
                struct.pack_into("<QQQQ", data, o + 24, vmaddr, vmsize, fileoff, filesize)

    with open(path, "wb") as f:
        f.write(data)

    # Verify our own work.
    (newstroff,) = struct.unpack_from("<IIII", data, _find_symtab(data) + 8)[2:3]
    if newstroff % 8 != 0:
        fail(f"post-condition failed: stroff={newstroff} still mis-aligned")
    print(f"realign-linkedit: done (stroff={newstroff}, 8-aligned)")


def _find_symtab(data):
    (ncmds,) = struct.unpack_from("<I", data, 16)
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SYMTAB:
            return off
        off += cmdsize
    fail("LC_SYMTAB vanished after patch")


if __name__ == "__main__":
    main()

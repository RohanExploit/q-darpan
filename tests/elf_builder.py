"""Minimal ELF64 writer for tests.

Building an ELF by hand rather than shipping a compiled fixture keeps the test
suite honest on every platform: the ELF collector gets exercised on a Windows
analyst laptop with no cross-compiler installed, and the bytes under test are
visible in the repository instead of opaque.

Only what pyelftools needs to parse sections and dynamic entries is emitted --
this is a fixture, not a linker.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

ELF_MAGIC = b"\x7fELF"

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_DYNSYM = 11

SHF_ALLOC = 0x2
SHF_WRITE = 0x1

DT_NEEDED = 1
DT_STRTAB = 5
DT_SYMTAB = 6
DT_NULL = 0

_SH_ENTSIZE = 64
_EH_SIZE = 64


class _StringTable:
    """A NUL-separated string table with de-duplicated offsets."""

    def __init__(self) -> None:
        self._buffer = bytearray(b"\x00")
        self._offsets: Dict[str, int] = {"": 0}

    def add(self, value: str) -> int:
        if value in self._offsets:
            return self._offsets[value]
        offset = len(self._buffer)
        self._buffer.extend(value.encode("utf-8") + b"\x00")
        self._offsets[value] = offset
        return offset

    def data(self) -> bytes:
        return bytes(self._buffer)


def build_elf(
    path: Path,
    *,
    rodata: bytes = b"",
    needed: Sequence[str] = (),
    symbols: Sequence[str] = (),
) -> Path:
    """Write a minimal ELF64 object.

    ``rodata`` lands in a real ``.rodata`` section so constant search has
    somewhere to look; ``needed`` becomes ``DT_NEEDED`` entries; ``symbols``
    become ``.dynsym`` entries.
    """
    shstrtab = _StringTable()
    dynstr = _StringTable()

    sections: List[Tuple[str, int, int, bytes, int, int]] = []
    # (name, type, flags, data, link_index_placeholder, entsize)

    sections.append(("", SHT_NULL, 0, b"", 0, 0))

    if rodata:
        sections.append((".rodata", SHT_PROGBITS, SHF_ALLOC, rodata, 0, 0))

    dynstr_index: Optional[int] = None
    if needed or symbols:
        for name in needed:
            dynstr.add(name)
        for name in symbols:
            dynstr.add(name)

        # .dynsym: a null entry followed by one entry per symbol.
        dynsym = bytearray(b"\x00" * 24)
        for name in symbols:
            dynsym.extend(
                struct.pack(
                    "<IBBHQQ",
                    dynstr.add(name),  # st_name
                    0x12,              # st_info: GLOBAL FUNC
                    0,                 # st_other
                    1,                 # st_shndx
                    0,                 # st_value
                    0,                 # st_size
                )
            )

        dynamic = bytearray()
        for name in needed:
            dynamic.extend(struct.pack("<qQ", DT_NEEDED, dynstr.add(name)))
        dynamic.extend(struct.pack("<qQ", DT_NULL, 0))

        sections.append((".dynstr", SHT_STRTAB, SHF_ALLOC, dynstr.data(), 0, 0))
        dynstr_index = len(sections) - 1
        sections.append((".dynsym", SHT_DYNSYM, SHF_ALLOC, bytes(dynsym), dynstr_index, 24))
        sections.append((".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, bytes(dynamic), dynstr_index, 16))

    sections.append((".shstrtab", SHT_STRTAB, 0, b"", 0, 0))
    shstrtab_index = len(sections) - 1

    for name, *_ in sections:
        shstrtab.add(name)
    sections[shstrtab_index] = (".shstrtab", SHT_STRTAB, 0, shstrtab.data(), 0, 0)

    # Lay out section data after the ELF header, 16-byte aligned.
    offset = _EH_SIZE
    placed: List[Tuple[str, int, int, bytes, int, int, int]] = []
    for name, sh_type, flags, data, link, entsize in sections:
        if sh_type == SHT_NULL:
            placed.append((name, sh_type, flags, data, link, entsize, 0))
            continue
        padding = (-offset) % 16
        offset += padding
        placed.append((name, sh_type, flags, data, link, entsize, offset))
        offset += len(data)

    padding = (-offset) % 8
    offset += padding
    section_header_offset = offset

    body = bytearray()
    cursor = _EH_SIZE
    for name, sh_type, flags, data, link, entsize, data_offset in placed:
        if sh_type == SHT_NULL:
            continue
        body.extend(b"\x00" * (data_offset - cursor))
        body.extend(data)
        cursor = data_offset + len(data)
    body.extend(b"\x00" * (section_header_offset - cursor))

    header = bytearray()
    header.extend(ELF_MAGIC)
    header.extend(bytes([2, 1, 1, 0]))     # 64-bit, little-endian, v1, SysV
    header.extend(b"\x00" * 8)
    header.extend(
        struct.pack(
            "<HHIQQQIHHHHHH",
            3,                            # e_type: ET_DYN
            62,                           # e_machine: x86-64
            1,                            # e_version
            0,                            # e_entry
            0,                            # e_phoff
            section_header_offset,        # e_shoff
            0,                            # e_flags
            _EH_SIZE,                     # e_ehsize
            0,                            # e_phentsize
            0,                            # e_phnum
            _SH_ENTSIZE,                  # e_shentsize
            len(placed),                  # e_shnum
            shstrtab_index,               # e_shstrndx
        )
    )

    table = bytearray()
    for name, sh_type, flags, data, link, entsize, data_offset in placed:
        table.extend(
            struct.pack(
                "<IIQQQQIIQQ",
                shstrtab.add(name),                    # sh_name
                sh_type,                               # sh_type
                flags,                                 # sh_flags
                data_offset if flags & SHF_ALLOC else 0,  # sh_addr
                data_offset,                           # sh_offset
                len(data),                             # sh_size
                link,                                  # sh_link
                0,                                     # sh_info
                1,                                     # sh_addralign
                entsize,                               # sh_entsize
            )
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(bytes(header) + bytes(body) + bytes(table))
    return path


#: The AES forward S-box opening bytes, matching const.aes.sbox in the rules.
AES_SBOX = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")

#: SHA-256 round constants K[0..3], matching const.sha256.k.
SHA256_K = bytes.fromhex("428a2f9871374491b5c0fbcfe9b5dba5")

#: MD5 T-table, big-endian words, matching const.md5.t_be.
MD5_T = bytes.fromhex("d76aa478e8c7b756242070dbc1bdceee")

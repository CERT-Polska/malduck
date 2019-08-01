# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from .bits import rol, ror, align, align_down
from .crypto.xor import xor
from .disasm import disasm
from .hash.crc import crc32
from .hash.sha import md5, sha1, sha224, sha384, sha256, sha512
from .string.inet import ipv4
from .string.ops import asciiz, utf16z, chunks, enhex, unhex, uleb128
from .structure import Structure

from .pe import pe2cuckoo

from .procmem import (
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY
)

from .short import (
    aes, blowfish, des3, rc4, pe, aplib, gzip, procmem, procmempe, procmemelf, cuckoomem, pad, unpad,
    insn, rsa, verify, base64, rabbit, serpent, lznt1, pkcs7, unpkcs7
)

from .string.bin import (
    uint8, uint16, uint32, uint64,
    u8, u16, u32, u64,
    p8, p16, p32, p64,
    bigint, pack, unpack
)

from .ints import (
    QWORD, DWORD, WORD, BYTE, CHAR,
    UInt64, UInt32, UInt16, UInt8,
    Int64, Int32, Int16, Int8
)

from .yara import (
    Yara, YaraString
)

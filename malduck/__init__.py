# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from .bits import rol, ror, align, align_down

from .compression.aplib import aplib
from .compression.gzip import gzip
from .compression.lznt1 import lznt1

from .crypto.aes import aes
from .crypto.blowfish import blowfish
from .crypto.des3 import des3
from .crypto.rabbit import rabbit
from .crypto.rc import rc4
from .crypto.rsa import rsa
from .crypto.serpent import serpent
from .crypto.xor import xor

from .disasm import disasm, insn

from .hash.crc import crc32
from .hash.sha import md5, sha1, sha224, sha384, sha256, sha512

from .ints import (
    QWORD, DWORD, WORD, BYTE, CHAR,
    UInt64, UInt32, UInt16, UInt8,
    Int64, Int32, Int16, Int8
)

from .pe import pe, pe2cuckoo

from .procmem import (
    procmem, procmempe, procmemelf, cuckoomem, idamem,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY
)

from .string.bin import (
    uint8, uint16, uint32, uint64,
    u8, u16, u32, u64,
    p8, p16, p32, p64,
    bigint, pack, unpack
)
from .string.inet import ipv4
from .string.ops import (
    asciiz, utf16z, chunks, chunks_iter, enhex, unhex, uleb128, base64,
    pad, unpad, pkcs7, unpkcs7
)

from .structure import Structure

from .verify import verify

from .yara import (
    Yara, YaraString
)

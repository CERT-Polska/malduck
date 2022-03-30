# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from .bits import align, align_down, rol, ror
from .compression import aplib, gzip, lznt1
from .crypto import (aes, blowfish, camellia, chacha20, des3, rabbit, rc4, rsa,
                     salsa20, serpent, xor)
from .disasm import disasm, insn
from .extractor import Extractor
from .hash import crc32, md5, sha1, sha224, sha256, sha384, sha512
from .ints import (BYTE, CHAR, DWORD, QWORD, WORD, Int8, Int16, Int32, Int64,
                   UInt8, UInt16, UInt32, UInt64)
from .pe import pe
from .procmem import (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
                      PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE,
                      PAGE_WRITECOPY, cuckoomem, idamem, procmem, procmemelf,
                      procmempe)
from .string import (asciiz, base64, bigint, chunks, chunks_iter, enhex, i8,
                     i8be, i16, i16be, i32, i32be, i64, i64be, int8, int8be,
                     int16, int16be, int32, int32be, int64, int64be, ipv4, p8,
                     p8be, p16, p16be, p32, p32be, p64, p64be, pack, pad,
                     pkcs7, u8, u8be, u16, u16be, u32, u32be, u64, u64be,
                     uint8, uint8be, uint16, uint16be, uint32, uint32be,
                     uint64, uint64be, uleb128, unhex, unpack, unpad, unpkcs7,
                     utf16z)
from .structure import Structure
from .verify import verify
from .yara import Yara, YaraString, YaraStringMatch

__all__ = [
    # bits
    "rol",
    "ror",
    "align",
    "align_down",
    # compression
    "aplib",
    "gzip",
    "lznt1",
    # crypto
    "aes",
    "camellia",
    "blowfish",
    "chacha20",
    "des3",
    "rabbit",
    "rc4",
    "rsa",
    "salsa20",
    "serpent",
    "xor",
    # disasm
    "disasm",
    "insn",
    # extractor
    "Extractor",
    # hash
    "crc32",
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    # ints
    "QWORD",
    "DWORD",
    "WORD",
    "BYTE",
    "CHAR",
    "UInt64",
    "UInt32",
    "UInt16",
    "UInt8",
    "Int64",
    "Int32",
    "Int16",
    "Int8",
    # pe
    "pe",
    # procmem
    "procmem",
    "procmempe",
    "procmemelf",
    "cuckoomem",
    "idamem",
    "PAGE_READONLY",
    "PAGE_READWRITE",
    "PAGE_WRITECOPY",
    "PAGE_EXECUTE",
    "PAGE_EXECUTE_READ",
    "PAGE_EXECUTE_READWRITE",
    "PAGE_EXECUTE_WRITECOPY",
    # string
    "uint64",
    "uint32",
    "uint16",
    "uint8",
    "uint64be",
    "uint32be",
    "uint16be",
    "uint8be",
    "u64",
    "u32",
    "u16",
    "u8",
    "u64be",
    "u32be",
    "u16be",
    "u8be",
    "int64",
    "int32",
    "int16",
    "int8",
    "int64be",
    "int32be",
    "int16be",
    "int8be",
    "i64",
    "i32",
    "i16",
    "i8",
    "i64be",
    "i32be",
    "i16be",
    "i8be",
    "p64",
    "p32",
    "p16",
    "p8",
    "p64be",
    "p32be",
    "p16be",
    "p8be",
    "bigint",
    "unpack",
    "pack",
    "ipv4",
    "asciiz",
    "chunks_iter",
    "chunks",
    "utf16z",
    "enhex",
    "unhex",
    "uleb128",
    "base64",
    "pad",
    "pkcs7",
    "unpad",
    "unpkcs7",
    # structure
    "Structure",
    # verify
    "verify",
    # yara
    "YaraStringMatch",
    "YaraString",
    "Yara",
]

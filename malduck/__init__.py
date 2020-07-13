# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from .bits import rol, ror, align, align_down

from .compression import aplib, gzip, lznt1

from .crypto import aes, blowfish, des3, rabbit, rc4, rsa, serpent, xor

from .disasm import disasm, insn

from .extractor import Extractor

from .hash import crc32, md5, sha1, sha224, sha256, sha384, sha512

from .ints import (
    QWORD,
    DWORD,
    WORD,
    BYTE,
    CHAR,
    UInt64,
    UInt32,
    UInt16,
    UInt8,
    Int64,
    Int32,
    Int16,
    Int8,
)

from .pe import pe

from .procmem import (
    procmem,
    procmempe,
    procmemelf,
    cuckoomem,
    idamem,
    PAGE_READONLY,
    PAGE_READWRITE,
    PAGE_WRITECOPY,
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
)

from .string import (
    uint64,
    uint32,
    uint16,
    uint8,
    uint64be,
    uint32be,
    uint16be,
    uint8be,
    u64,
    u32,
    u16,
    u8,
    u64be,
    u32be,
    u16be,
    u8be,
    int64,
    int32,
    int16,
    int8,
    int64be,
    int32be,
    int16be,
    int8be,
    i64,
    i32,
    i16,
    i8,
    i64be,
    i32be,
    i16be,
    i8be,
    p64,
    p32,
    p16,
    p8,
    p64be,
    p32be,
    p16be,
    p8be,
    bigint,
    unpack,
    pack,
    ipv4,
    asciiz,
    chunks_iter,
    chunks,
    utf16z,
    enhex,
    unhex,
    uleb128,
    base64,
    pad,
    pkcs7,
    unpad,
    unpkcs7,
)

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
    "blowfish",
    "des3",
    "rabbit",
    "rc4",
    "rsa",
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

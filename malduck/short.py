# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.
import warnings

from .compression.aplib import aPLib, aplib
from .compression.gzip import Gzip, gzip
from .compression.lznt1 import Lznt1, lznt1
from .crypto.aes import AES, aes
from .crypto.blowfish import Blowfish, blowfish
from .crypto.des3 import DES3, des3
from .crypto.serpent import Serpent, serpent
from .crypto.rabbit import Rabbit, rabbit
from .crypto.rc import RC4, rc4
from .crypto.rsa import RSA, rsa
from .disasm import Instruction, insn
from .pe import PE, pe
from .procmem.procmem import ProcessMemory, procmem
from .procmem.procmempe import ProcessMemoryPE, procmempe
from .procmem.procmemelf import ProcessMemoryELF, procmemelf
from .procmem.cuckoomem import CuckooProcessMemory, cuckoomem
from .procmem.idamem import IDAProcessMemory, idamem
from .string.ops import Padding, Unpadding, Base64, base64, pad, unpad, pkcs7, unpkcs7
from .verify import Verify, verify

warnings.warn(
    "malduck.short module is deprecated, please use shortened variants directly from malduck module",
    DeprecationWarning,
)

__all__ = [
    "aPLib",
    "aplib",
    "Gzip",
    "gzip",
    "Lznt1",
    "lznt1",
    "AES",
    "aes",
    "Blowfish",
    "blowfish",
    "DES3",
    "des3",
    "Serpent",
    "serpent",
    "Rabbit",
    "rabbit",
    "RC4",
    "rc4",
    "RSA",
    "rsa",
    "Instruction",
    "insn",
    "PE",
    "pe",
    "ProcessMemory",
    "ProcessMemoryPE",
    "ProcessMemoryELF",
    "CuckooProcessMemory",
    "IDAProcessMemory",
    "procmem",
    "procmempe",
    "procmemelf",
    "cuckoomem",
    "idamem",
    "Padding",
    "Unpadding",
    "Base64",
    "base64",
    "pad",
    "unpad",
    "pkcs7",
    "unpkcs7",
    "Verify",
    "verify",
]

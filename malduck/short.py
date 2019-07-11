# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from .compression.aplib import aPLib
from .compression.gzip import Gzip
from .compression.lznt1 import Lznt1
from .crypto.aes import AES
from .crypto.blowfish import Blowfish
from .crypto.des3 import DES3
from .crypto.serpent import Serpent
from .crypto.rabbit import Rabbit
from .crypto.rc import RC4
from .crypto.rsa import RSA
from .disasm import Instruction
from .pe import PE
from .procmem import ProcessMemory, ProcessMemoryPE, CuckooProcessMemory
from .string.ops import Padding, Unpadding, Base64
from .verify import Verify


class aes(object):
    def __init__(self, mode):
        self.mode = mode

    def decrypt(self, key=None, iv=None, data=None):
        return AES(key, iv, self.mode).decrypt(data)

    class _cbc_(object):
        @staticmethod
        def decrypt(key=None, iv=None, data=None):
            return aes("cbc").decrypt(key, iv, data)

        __call__ = decrypt

    cbc = _cbc_()

    class _ecb_(object):
        @staticmethod
        def decrypt(key=None, data=None):
            return aes("ecb").decrypt(key, None, data)

        __call__ = decrypt

    ecb = _ecb_()

    class _ctr_(object):
        @staticmethod
        def decrypt(key=None, nonce=None, data=None):
            return aes("ctr").decrypt(key, nonce, data)

        __call__ = decrypt

    ctr = _ctr_()

    @staticmethod
    def import_key(data):
        return AES.import_key(data)


class des3(object):
    def __init__(self, mode):
        self.mode = mode

    def decrypt(self, key=None, iv=None, data=None):
        return DES3(key, iv, self.mode).decrypt(data)

    class _cbc_(object):
        @staticmethod
        def decrypt(key=None, iv=None, data=None):
            return des3("cbc").decrypt(key, iv, data)

        __call__ = decrypt

    cbc = _cbc_()


class rc4_(object):
    @staticmethod
    def rc4(key, data):
        return RC4(key).encrypt(data)

    __call__ = decrypt = encrypt = rc4


class blowfish_(object):
    @staticmethod
    def decrypt(key, data):
        return Blowfish(key).decrypt(data)

    __call__ = decrypt


class rabbit_(object):
    @staticmethod
    def rabbit(key, iv, data):
        return Rabbit(key, iv).encrypt(data)

    __call__ = rabbit


def serpent(key, data, iv=None):
    return Serpent(key, iv).decrypt(data)


blowfish = blowfish_()
rc4 = rc4_()
rabbit = rabbit_()
pe = PE
aplib = aPLib()
procmem = ProcessMemory
procmempe = ProcessMemoryPE
cuckoomem = CuckooProcessMemory
base64 = Base64()
pad = Padding("pkcs7")
unpad = Unpadding("pkcs7")
insn = Instruction
rsa = RSA
verify = Verify
gzip = Gzip()
lznt1 = Lznt1()

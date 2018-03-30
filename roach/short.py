# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach.compression.aplib import aPLib
from roach.compression.gzip import Gzip
from roach.crypto.aes import AES
from roach.crypto.blowfish import Blowfish
from roach.crypto.des3 import DES3
from roach.crypto.rc import RC4
from roach.crypto.rsa import RSA
from roach.disasm import Instruction
from roach.pe import PE
from roach.procmem import ProcessMemory, ProcessMemoryPE
from roach.string.ops import Padding, Unpadding, Base64
from roach.verify import Verify

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

blowfish = blowfish_()
rc4 = rc4_()
pe = PE
aplib = aPLib()
procmem = ProcessMemory
procmempe = ProcessMemoryPE
base64 = Base64()
pad = Padding("pkcs7")
unpad = Unpadding("pkcs7")
insn = Instruction
rsa = RSA
verify = Verify
gzip = Gzip()

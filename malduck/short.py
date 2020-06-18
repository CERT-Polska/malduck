# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from .compression.aplib import aPLib
from .compression.gzip import Gzip
from .compression.lznt1 import Lznt1
from .crypto.aes import AES, Aes as aes
from .crypto.blowfish import Blowfish
from .crypto.des3 import DES3
from .crypto.serpent import Serpent
from .crypto.rabbit import Rabbit
from .crypto.rc import RC4
from .crypto.rsa import RSA
from .disasm import Instruction
from .pe import PE
from .procmem import ProcessMemory, ProcessMemoryPE, ProcessMemoryELF, CuckooProcessMemory, IDAProcessMemory
from .string.ops import Padding, Unpadding, Base64
from .verify import Verify


class des3(object):
    def __init__(self, mode):
        self.mode = mode

    def decrypt(self, key=None, iv=None, data=None):
        return DES3(key, iv, self.mode).decrypt(data)

    def encrypt(self, key=None, iv=None, data=None):
        return DES3(key, iv, self.mode).encrypt(data)

    class _cbc_(object):
        r"""
        DES3 decryption object (CBC-only)

        .. code-block:: python

            from malduck import des3

            des3.cbc(key=b'des3_key',
                     iv=b"iv"*4,
                     data=b"_encrypted_data_")

        :param key: Encryption key
        :type key: bytes
        :param iv: Initialization vector
        :type iv: bytes
        :param data: Buffer containing data to decrypt
        :type data: bytes
        """
        @staticmethod
        def decrypt(key=None, iv=None, data=None):
            return des3("cbc").decrypt(key, iv, data)

        @staticmethod
        def encrypt(key=None, iv=None, data=None):
            return des3("cbc").encrypt(key, iv, data)

        __call__ = decrypt

    cbc = _cbc_()


class rc4_(object):
    r"""
    RC4 decryption

    .. code-block:: python

        from malduck import rc4

        rc4(b"rc4_key", b"rc4_data_to_decrypt")

    :param key: Encryption key
    :type key: bytes
    :param data: Buffer containing data to decrypt
    :type data: bytes
    """

    @staticmethod
    def rc4(key, data):
        return RC4(key).encrypt(data)

    __call__ = decrypt = encrypt = rc4


class blowfish_(object):
    r"""
    Blowfish decryption (ECB-only)

    .. code-block:: python

        from malduck import blowfish

        blowfish(b"blowfish", b"\x91;\x92\xa9\x85\x83\xb36\xbb\xac\xa8r0\xf1$\x19")

    :param key: Encryption key
    :type key: bytes
    :param data: Buffer containing data to decrypt
    :type data: bytes
    """
    @staticmethod
    def decrypt(key, data):
        return Blowfish(key).decrypt(data)

    @staticmethod
    def encrypt(key, data):
        return Blowfish(key).encrypt(data)

    __call__ = decrypt


class rabbit_(object):
    r"""
    Rabbit decryption

    :param key: Encryption key
    :type key: bytes
    :param iv: Initialization vector
    :type iv: bytes
    :param data: Buffer containing data to decrypt
    :type data: bytes
    """

    @staticmethod
    def rabbit(key, iv, data):
        return Rabbit(key, iv).encrypt(data)

    __call__ = rabbit


class serpent(object):
    r"""
     Serpent decryption

     .. code-block:: python

         from malduck import serpent

         serpent(
            b"012345678901_key",
            unhex("8a516cb035540b5854a18eeccc40299d"),
            iv=None # null-bytes
         )

     :param key: Encryption key
     :type key: bytes
     :param data: Buffer containing data to decrypt
     :type data: bytes
     :param iv: Initialization vector (default: :code:`b"\x00" * 16`)
     :type iv: bytes
     """

    @staticmethod
    def decrypt(key, data, iv=None):
        return Serpent(key, iv).decrypt(data)

    @staticmethod
    def encrypt(key, data, iv=None):
        return Serpent(key, iv).encrypt(data)

    __call__ = decrypt


blowfish = blowfish_()
rc4 = rc4_()
rabbit = rabbit_()
pe = PE
aplib = aPLib()
procmem = ProcessMemory
procmempe = ProcessMemoryPE
procmemelf = ProcessMemoryELF
cuckoomem = CuckooProcessMemory
idamem = IDAProcessMemory
base64 = Base64()
pad = Padding("pkcs7")
pkcs7 = Padding("pkcs7")
unpad = Unpadding("pkcs7")
unpkcs7 = Unpadding("pkcs7")
insn = Instruction
rsa = RSA
verify = Verify
gzip = Gzip()
lznt1 = Lznt1()

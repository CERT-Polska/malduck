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
from .procmem import ProcessMemory, ProcessMemoryPE, ProcessMemoryELF, CuckooProcessMemory
from .string.ops import Padding, Unpadding, Base64
from .verify import Verify


class aes(object):

    def __init__(self, mode):
        self.mode = mode

    def decrypt(self, key=None, iv=None, data=None):
        return AES(key, iv, self.mode).decrypt(data)

    class _cbc_(object):
        """
        AES decryption using CBC mode

        .. code-block:: python

            from malduck import aes, pkcs7

            aes.cbc(key=b'aes128cipher_key',
                    iv=b"iv"*8,
                    data=pkcs7(b"data_to_be_encrypted", 16))
        """
        @staticmethod
        def decrypt(key=None, iv=None, data=None):
            return aes("cbc").decrypt(key, iv, data)

        __call__ = decrypt

    cbc = _cbc_()

    class _ecb_(object):
        """
        AES decryption using ECB mode

        .. code-block:: python

            from malduck import aes, pkcs7

            aes.ecb(key=b'aes128cipher_key',
                    data=pkcs7(b"data_to_be_encrypted", 16))
        """
        @staticmethod
        def decrypt(key=None, data=None):
            return aes("ecb").decrypt(key, None, data)

        __call__ = decrypt

    ecb = _ecb_()

    class _ctr_(object):
        """
        AES decryption using CTR mode

        .. code-block:: python

            from malduck import aes, pkcs7

            aes.ctr(key=b'aes128cipher_key',
                    nonce=b"iv"*8
                    data=pkcs7(b"data_to_be_encrypted", 16))
        """
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


def serpent(key, data, iv=None):
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
    return Serpent(key, iv).decrypt(data)


blowfish = blowfish_()
rc4 = rc4_()
rabbit = rabbit_()
pe = PE
aplib = aPLib()
procmem = ProcessMemory
procmempe = ProcessMemoryPE
procmemelf = ProcessMemoryELF
cuckoomem = CuckooProcessMemory
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

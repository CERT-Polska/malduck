# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import io
import warnings

from Cryptodome.Cipher import AES as AESCipher

from .winhdr import BLOBHEADER, BaseBlob
from ..string.bin import uint32

__all__ = ["PlaintextKeyBlob", "AES", "aes"]


class PlaintextKeyBlob(BaseBlob):
    r"""
    `BLOB` object (`PLAINTEXTKEYBLOB`) for `CALG_AES`

    .. seealso:: :class:`malduck.crypto.BLOBHEADER`
    """
    types = {
        16: "AES-128",
        24: "AES-192",
        32: "AES-256",
    }

    def __init__(self):
        BaseBlob.__init__(self)
        self.key = None

    def parse(self, buf):
        """
        Parse structure from buffer

        :param buf: Buffer with structure data
        :type buf: :class:`io.BytesIO`
        """
        length = uint32(buf.read(4))
        value = buf.read()
        if length != len(value):
            return
        self.key = value

    def export_key(self):
        """
        Exports key from structure

        :return: Tuple (`algorithm`, `key`). `Algorithm` is one of: "AES-128", "AES-192", "AES-256"
        :rtype: Tuple[str, bytes]
        """
        return self.types[len(self.key)], self.key


BlobTypes = {
    8: PlaintextKeyBlob,
}


class AesCbc(object):
    def encrypt(self, key, iv, data):
        """
        Encrypts buffer using AES algorithm in CBC mode.

        :param key: Cryptographic key (128, 192 or 256 bits)
        :type key: bytes
        :param iv: Initialization vector
        :type iv: bytes
        :param data: Buffer to be encrypted
        :type data: bytes
        :return: Encrypted data
        :rtype: bytes
        """
        cipher = AESCipher.new(key, AESCipher.MODE_CBC, iv=iv)
        return cipher.encrypt(data)

    def decrypt(self, key, iv, data):
        """
        Decrypts buffer using AES algorithm in CBC mode.

        :param key: Cryptographic key (128, 192 or 256 bits)
        :type key: bytes
        :param iv: Initialization vector
        :type iv: bytes
        :param data: Buffer to be decrypted
        :type data: bytes
        :return: Decrypted data
        :rtype: bytes
        """
        cipher = AESCipher.new(key, AESCipher.MODE_CBC, iv=iv)
        return cipher.decrypt(data)

    def __call__(self, key, iv, data):
        warnings.warn(
            "malduck.aes.cbc() is deprecated, please use malduck.aes.cbc.decrypt()",
            DeprecationWarning,
        )
        return self.decrypt(key, iv, data)


class AesEcb(object):
    def encrypt(self, key, data):
        """
        Encrypts buffer using AES algorithm in ECB mode.

        :param key: Cryptographic key (128, 192 or 256 bits)
        :type key: bytes
        :param data: Buffer to be encrypted
        :type data: bytes
        :return: Encrypted data
        :rtype: bytes
        """
        cipher = AESCipher.new(key, AESCipher.MODE_ECB)
        return cipher.encrypt(data)

    def decrypt(self, key, data):
        """
        Decrypts buffer using AES algorithm in ECB mode.

        :param key: Cryptographic key (128, 192 or 256 bits)
        :type key: bytes
        :param data: Buffer to be decrypted
        :type data: bytes
        :return: Decrypted data
        :rtype: bytes
        """
        cipher = AESCipher.new(key, AESCipher.MODE_ECB)
        return cipher.decrypt(data)

    def __call__(self, key, iv, data):
        warnings.warn(
            "malduck.aes.ecb() is deprecated, please use malduck.aes.ecb.decrypt()",
            DeprecationWarning,
        )
        return self.decrypt(key, data)


class AesCtr(object):
    def encrypt(self, key, nonce, data):
        """
        Encrypts buffer using AES algorithm in CTR mode.

        :param key: Cryptographic key (128, 192 or 256 bits)
        :type key: bytes
        :param nonce: Initial counter value, big-endian encoded
        :type nonce: bytes
        :param data: Buffer to be encrypted
        :type data: bytes
        :return: Encrypted data
        :rtype: bytes
        """
        cipher = AESCipher.new(key, AESCipher.MODE_CTR, nonce=b"", initial_value=nonce)
        return cipher.encrypt(data)

    def decrypt(self, key, nonce, data):
        """
        Decrypts buffer using AES algorithm in CTR mode.

        :param key: Cryptographic key (128, 192 or 256 bits)
        :type key: bytes
        :param nonce: Initial counter value, big-endian encoded
        :type nonce: bytes
        :param data: Buffer to be decrypted
        :type data: bytes
        :return: Decrypted data
        :rtype: bytes
        """
        cipher = AESCipher.new(key, AESCipher.MODE_CTR, nonce=b"", initial_value=nonce)
        return cipher.decrypt(data)

    def __call__(self, key, nonce, data):
        warnings.warn(
            "malduck.aes.ctr() is deprecated, please use malduck.aes.ctr.decrypt()",
            DeprecationWarning,
        )
        return self.decrypt(key, nonce, data)


class Aes(object):
    cbc = AesCbc()
    ecb = AesEcb()
    ctr = AesCtr()

    def encrypt(self, key, iv, data):
        warnings.warn(
            "malduck.aes.encrypt is deprecated, please use malduck.aes.cbc.encrypt",
            DeprecationWarning,
        )
        return self.cbc.encrypt(key, iv, data)

    def decrypt(self, key, iv, data):
        warnings.warn(
            "malduck.aes.decrypt is deprecated, please use malduck.aes.cbc.decrypt",
            DeprecationWarning,
        )
        return self.cbc.decrypt(key, iv, data)

    def __call__(self, mode):
        warnings.warn(
            "malduck.aes('<mode>') is deprecated, please use malduck.aes.<mode>",
            DeprecationWarning,
        )
        return getattr(self, mode)

    @staticmethod
    def import_key(data):
        """
        Extracts key from buffer containing :class:`PlaintextKeyBlob` data

        :param data: Buffer with `BLOB` structure data
        :type data: bytes
        :return: Tuple (`algorithm`, `key`). `Algorithm` is one of: "AES-128", "AES-192", "AES-256"
        """
        if len(data) < BLOBHEADER.sizeof():
            return

        buf = io.BytesIO(data)
        header = BLOBHEADER.parse(buf.read(BLOBHEADER.sizeof()))

        algorithms = (
            0x0000660E,  # AES 128
            0x0000660F,  # AES 192
            0x00006610,  # AES 256
        )

        if header.bType not in BlobTypes:
            return

        if header.aiKeyAlg not in algorithms:
            return

        obj = BlobTypes[header.bType]()
        obj.parse(buf)
        return obj.export_key()


class AES(object):
    r"""
    AES encryption/decryption object

    Deprecated, use `malduck.aes`

    :param key: Encryption key
    :type key: bytes
    :param iv: Initialization vector (IV for CBC mode, nonce for CTR)
    :type iv: bytes, optional
    :param mode: Block cipher mode (default: "cbc")
    :type mode: str ("cbc", "ecb", "ctr")
    """
    algorithms = (
        0x0000660E,  # AES 128
        0x0000660F,  # AES 192
        0x00006610,  # AES 256
    )

    modes = {
        "cbc": Aes.cbc,
        "ecb": Aes.ecb,
        "ctr": Aes.ctr,
    }

    def __init__(self, key, iv=None, mode="cbc"):
        warnings.warn(
            "malduck.crypto.AES is deprecated, please use malduck.aes.<mode> variants",
            DeprecationWarning,
        )
        self.key = key
        self.iv = iv
        self.mode = mode
        self.aes = self.modes[mode]

    def encrypt(self, data):
        """
        Encrypt provided data

        :param data: Buffer with data
        :type data: bytes
        :return: Encrypted data
        """
        if self.mode == "ecb":
            return self.aes.encrypt(self.key, data)
        else:
            return self.aes.encrypt(self.key, self.iv, data)

    def decrypt(self, data):
        """
        Decrypt provided data

        :param data: Buffer with encrypted data
        :type data: bytes
        :return: Decrypted data
        """
        if self.mode == "ecb":
            return self.aes.decrypt(self.key, data)
        else:
            return self.aes.decrypt(self.key, self.iv, data)

    @staticmethod
    def import_key(data):
        """
        Extracts key from buffer containing :class:`PlaintextKeyBlob` data

        :param data: Buffer with `BLOB` structure data
        :type data: bytes
        :return: Tuple (`algorithm`, `key`). `Algorithm` is one of: "AES-128", "AES-192", "AES-256"
        """
        return Aes.import_key(data)


aes = Aes()

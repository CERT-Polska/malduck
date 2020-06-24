# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import io

from typing import Optional, Tuple

from Cryptodome.Cipher import AES as AESCipher

from .winhdr import BLOBHEADER, BaseBlob
from ..string.bin import uint32

__all__ = ["PlaintextKeyBlob", "aes"]


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

    def __init__(self) -> None:
        BaseBlob.__init__(self)
        self.key: Optional[bytes] = None

    def parse(self, buf: io.BytesIO) -> None:
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

    def export_key(self) -> Optional[Tuple[str, bytes]]:
        """
        Exports key from structure or returns None if no key was imported

        :return: Tuple (`algorithm`, `key`). `Algorithm` is one of: "AES-128", "AES-192", "AES-256"
        :rtype: Tuple[str, bytes]
        """
        if self.key is not None:
            return self.types[len(self.key)], self.key

        return None


BlobTypes = {
    8: PlaintextKeyBlob,
}


class AesCbc:
    def encrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
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

    def decrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
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


class AesEcb:
    def encrypt(self, key: bytes, data: bytes) -> bytes:
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

    def decrypt(self, key: bytes, data: bytes) -> bytes:
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


class AesCtr:
    def encrypt(self, key: bytes, nonce: bytes, data: bytes) -> bytes:
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

    def decrypt(self, key: bytes, nonce: bytes, data: bytes) -> bytes:
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


class Aes:
    cbc = AesCbc()
    ecb = AesEcb()
    ctr = AesCtr()

    @staticmethod
    def import_key(data: bytes) -> Optional[Tuple[str, bytes]]:
        """
        Extracts key from buffer containing :class:`PlaintextKeyBlob` data

        :param data: Buffer with `BLOB` structure data
        :type data: bytes
        :return: Tuple (`algorithm`, `key`). `Algorithm` is one of: "AES-128", "AES-192", "AES-256"
        """
        if len(data) < BLOBHEADER.sizeof():
            return None

        buf = io.BytesIO(data)
        header = BLOBHEADER.parse(buf.read(BLOBHEADER.sizeof()))

        algorithms = (
            0x0000660E,  # AES 128
            0x0000660F,  # AES 192
            0x00006610,  # AES 256
        )

        if header.bType not in BlobTypes:
            return None

        if header.aiKeyAlg not in algorithms:
            return None

        obj = BlobTypes[header.bType]()
        obj.parse(buf)
        return obj.export_key()


aes = Aes()

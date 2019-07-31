# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import io

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .winhdr import BLOBHEADER, BaseBlob
from ..string.bin import uint32


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


class AES(object):
    r"""
    AES decryption object

    :param key: Encryption key
    :type key: bytes
    :param iv: Initialization vector (IV for CBC mode, nonce for CTR)
    :type iv: bytes, optional
    :param mode: Block cipher mode (default: "cbc")
    :type mode: str ("cbc", "ecb", "ctr")
    """
    algorithms = (
        0x0000660e,  # AES 128
        0x0000660f,  # AES 192
        0x00006610,  # AES 256
    )

    modes = {
        "cbc": lambda iv: modes.CBC(iv),
        "ecb": lambda iv: modes.ECB(),
        "ctr": lambda nonce: modes.CTR(nonce),
    }

    def __init__(self, key, iv=None, mode="cbc"):
        self.aes = Cipher(
            algorithms.AES(key), self.modes[mode](iv),
            backend=default_backend()
        ).decryptor()

    def decrypt(self, data):
        """
        Decrypt provided data

        :param data: Buffer with encrypted data
        :type data: bytes
        :return: Decrypted data
        """
        return self.aes.update(data) + self.aes.finalize()

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
        if header.bType not in BlobTypes:
            return

        if header.aiKeyAlg not in AES.algorithms:
            return

        obj = BlobTypes[header.bType]()
        obj.parse(buf)
        return obj.export_key()

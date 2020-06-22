# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import warnings

from Cryptodome.Cipher import DES, DES3 as DES3Cipher

__all__ = ["DES3", "des3"]


class Des3Cbc(object):
    def _get_cipher(self, key, iv):
        if len(key) == 8:
            # For 8 bytes it fallbacks to single DES
            # (original cryptography behaviour)
            return DES.new(key, DES.MODE_CBC, iv=iv)
        return DES3Cipher.new(key, DES3Cipher.MODE_CBC, iv=iv)

    def encrypt(self, key, iv, data):
        """
        Encrypts buffer using DES/DES3 algorithm in CBC mode.

        :param key: Cryptographic key (16 or 24 bytes, 8 bytes for single DES)
        :type key: bytes
        :param iv: Initialization vector
        :type iv: bytes
        :param data: Buffer to be encrypted
        :type data: bytes
        :return: Encrypted data
        :rtype: bytes
        """
        return self._get_cipher(key, iv).encrypt(data)

    def decrypt(self, key, iv, data):
        """
        Decrypts buffer using DES/DES3 algorithm in CBC mode.

        :param key: Cryptographic key (16 or 24 bytes, 8 bytes for single DES)
        :type key: bytes
        :param iv: Initialization vector
        :type iv: bytes
        :param data: Buffer to be decrypted
        :type data: bytes
        :return: Decrypted data
        :rtype: bytes
        """
        return self._get_cipher(key, iv).decrypt(data)

    def __call__(self, key, iv, data):
        warnings.warn(
            "malduck.des3.cbc() is deprecated, please use malduck.des3.cbc.decrypt()",
            DeprecationWarning,
        )
        return self.decrypt(key, iv, data)


class Des3(object):
    cbc = Des3Cbc()

    def encrypt(self, key, iv, data):
        warnings.warn(
            "malduck.des3.encrypt is deprecated, please use malduck.des3.cbc.encrypt",
            DeprecationWarning,
        )
        return self.cbc.encrypt(key, iv, data)

    def decrypt(self, key, iv, data):
        warnings.warn(
            "malduck.des3.decrypt is deprecated, please use malduck.des3.cbc.decrypt",
            DeprecationWarning,
        )
        return self.cbc.decrypt(key, iv, data)

    def __call__(self, mode):
        warnings.warn(
            "malduck.des3('<mode>') is deprecated, please use malduck.des3.<mode>",
            DeprecationWarning,
        )
        return getattr(self, mode)


class DES3(object):
    modes = {
        "cbc": Des3.cbc,
    }

    def __init__(self, key, iv=None, mode="cbc"):
        warnings.warn(
            "malduck.crypto.DES3 is deprecated, please use malduck.des3.<mode> variants",
            DeprecationWarning,
        )
        self.key = key
        self.iv = iv
        self.des3 = self.modes[mode]

    def decrypt(self, data):
        return self.des3.decrypt(self.key, self.iv, data)

    def encrypt(self, data):
        return self.des3.encrypt(self.key, self.iv, data)


des3 = Des3()

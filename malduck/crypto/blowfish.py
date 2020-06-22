# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import warnings

from Cryptodome.Cipher import Blowfish as BlowfishCipher

__all__ = ["Blowfish", "blowfish"]


class BlowfishEcb(object):
    def encrypt(self, key, data):
        """
        Encrypts buffer using Blowfish algorithm in ECB mode.

        :param key: Cryptographic key (4 to 56 bytes)
        :type key: bytes
        :param data: Buffer to be encrypted
        :type data: bytes
        :return: Encrypted data
        :rtype: bytes
        """
        cipher = BlowfishCipher.new(key, BlowfishCipher.MODE_ECB)
        return cipher.encrypt(data)

    def decrypt(self, key, data):
        """
        Decrypts buffer using Blowfish algorithm in ECB mode.

        :param key: Cryptographic key (4 to 56 bytes)
        :type key: bytes
        :param data: Buffer to be decrypted
        :type data: bytes
        :return: Decrypted data
        :rtype: bytes
        """
        cipher = BlowfishCipher.new(key, BlowfishCipher.MODE_ECB)
        return cipher.decrypt(data)


class _Blowfish(object):
    ecb = BlowfishEcb()

    def encrypt(self, key, data):
        warnings.warn(
            "malduck.blowfish.encrypt is deprecated, please use malduck.blowfish.ecb.encrypt",
            DeprecationWarning,
        )
        return self.ecb.encrypt(key, data)

    def decrypt(self, key, data):
        warnings.warn(
            "malduck.blowfish.decrypt is deprecated, please use malduck.blowfish.ecb.decrypt",
            DeprecationWarning,
        )
        return self.ecb.decrypt(key, data)

    def __call__(self, key, data):
        warnings.warn(
            "malduck.blowfish() is deprecated, please use malduck.blowfish.ecb.decrypt",
            DeprecationWarning,
        )
        return self.ecb.decrypt(key, data)


class Blowfish(object):
    def __init__(self, key):
        warnings.warn(
            "malduck.crypto.Blowfish is deprecated, please use malduck.blowfish.<mode> variants",
            DeprecationWarning,
        )
        self.key = key

    def decrypt(self, data):
        return _Blowfish.ecb.decrypt(self.key, data)

    def encrypt(self, data):
        return _Blowfish.ecb.encrypt(self.key, data)


blowfish = _Blowfish()

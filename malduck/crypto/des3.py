# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.
from typing import cast

from Cryptodome.Cipher import DES
from Cryptodome.Cipher import DES3 as DES3Cipher
from Cryptodome.Cipher._mode_cbc import CbcMode
from Cryptodome.Cipher._mode_ecb import EcbMode

__all__ = ["des3"]


class Des3Cbc:
    def _get_cipher(self, key: bytes, iv: bytes) -> CbcMode:
        if len(key) == 8:
            # For 8 bytes it fallbacks to single DES
            # (original cryptography behaviour)
            return cast(CbcMode, DES.new(key, DES.MODE_CBC, iv=iv))
        return cast(CbcMode, DES3Cipher.new(key, DES3Cipher.MODE_CBC, iv=iv))

    def encrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
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

    def decrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
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


class Des3Ecb:
    def _get_cipher(self, key: bytes) -> EcbMode:
        if len(key) == 8:
            # For 8 bytes it fallbacks to single DES
            # (original cryptography behaviour)
            return cast(EcbMode, DES.new(key, DES.MODE_ECB))
        return cast(EcbMode, DES3Cipher.new(key, DES3Cipher.MODE_ECB))

    def encrypt(self, key: bytes, data: bytes) -> bytes:
        """
        Encrypts buffer using DES/DES3 algorithm in ECB mode.

        :param key: Cryptographic key (16 or 24 bytes, 8 bytes for single DES)
        :type key: bytes
        :param data: Buffer to be encrypted
        :type data: bytes
        :return: Encrypted data
        :rtype: bytes
        """
        return self._get_cipher(key).encrypt(data)

    def decrypt(self, key: bytes, data: bytes) -> bytes:
        """
        Decrypts buffer using DES/DES3 algorithm in ECB mode.

        :param key: Cryptographic key (16 or 24 bytes, 8 bytes for single DES)
        :type key: bytes
        :param data: Buffer to be decrypted
        :type data: bytes
        :return: Decrypted data
        :rtype: bytes
        """
        return self._get_cipher(key).decrypt(data)


class Des3:
    cbc = Des3Cbc()
    ecb = Des3Ecb()


des3 = Des3()

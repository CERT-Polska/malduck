# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from Cryptodome.Cipher import Blowfish as BlowfishCipher

__all__ = ["blowfish"]


class BlowfishEcb:
    def encrypt(self, key: bytes, data: bytes) -> bytes:
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

    def decrypt(self, key: bytes, data: bytes) -> bytes:
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


class Blowfish:
    ecb = BlowfishEcb()


blowfish = Blowfish()

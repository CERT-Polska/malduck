# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from Cryptodome.Cipher import ARC4

__all__ = ["rc4"]

ARC4.key_size = range(3, 256 + 1)


def rc4(key: bytes, data: bytes) -> bytes:
    """
    Encrypts/decrypts buffer using RC4 algorithm

    :param key: Cryptographic key (from 3 to 256 bytes)
    :type key: bytes
    :param data: Buffer to be encrypted/decrypted
    :type data: bytes
    :return: Encrypted/decrypted data
    :rtype: bytes
    """
    return ARC4.new(key).decrypt(data)

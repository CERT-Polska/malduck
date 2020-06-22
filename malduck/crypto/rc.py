# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import warnings

from Cryptodome.Cipher import ARC4

__all__ = ["rc4", "RC4"]

ARC4.key_size = range(3, 256 + 1)


class RC4Cipher(object):
    """
    Encrypts/decrypts buffer using RC4 algorithm

    :param key: Cryptographic key (from 3 to 256 bytes)
    :type key: bytes
    :param data: Buffer to be encrypted/decrypted
    :type data: bytes
    :return: Encrypted/decrypted data
    :rtype: bytes
    """

    # todo: transform it to single rc4 function
    def __call__(self, key, data):
        return ARC4.new(key).decrypt(data)

    def rc4(self, key, data):
        warnings.warn(
            "malduck.rc4.rc4() is deprecated, please use malduck.rc4() or malduck.rc4.decrypt()",
            DeprecationWarning,
        )
        return self.decrypt(key, data)

    encrypt = decrypt = __call__


class RC4(object):
    # todo: remove whole class
    def __init__(self, key):
        warnings.warn(
            "malduck.RC4() is deprecated, please use malduck.rc4()", DeprecationWarning
        )
        self.key = key

    def rc4(self, data):
        return RC4Cipher().decrypt(self.key, data)

    encrypt = decrypt = rc4


rc4 = RC4Cipher()

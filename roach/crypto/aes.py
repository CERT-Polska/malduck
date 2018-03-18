# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class AES(object):
    modes = {
        "cbc": lambda iv: modes.CBC(iv),
        "ecb": lambda iv: modes.ECB(),
    }

    def __init__(self, key, iv=None, mode="cbc"):
        self.aes = Cipher(
            algorithms.AES(key), self.modes[mode](iv),
            backend=default_backend()
        ).decryptor()

    def decrypt(self, data):
        return self.aes.update(data) + self.aes.finalize()

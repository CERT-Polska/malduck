# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Blowfish(object):
    def __init__(self, key):
        self.blowfish = Cipher(
            algorithms.Blowfish(key), mode=modes.ECB(),
            backend=default_backend()
        ).decryptor()

    def decrypt(self, data):
        return self.blowfish.update(data) + self.blowfish.finalize()

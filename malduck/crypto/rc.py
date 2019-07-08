# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from Cryptodome.Cipher import ARC4

ARC4.key_size = range(3, 256+1)


class RC4(object):
    def __init__(self, key):
        self.key = key

    def rc4(self, data):
        return ARC4.new(self.key).encrypt(data)

    encrypt = decrypt = rc4

# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach.crypto.aes import AES

class aes(object):
    def __init__(self, mode):
        self.mode = mode

    def decrypt(self, key=None, iv=None, data=None):
        return AES(key, iv, self.mode).decrypt(data)

    class cbc(object):
        @staticmethod
        def decrypt(key=None, iv=None, data=None):
            return aes("cbc").decrypt(key, iv, data)

    class ecb(object):
        @staticmethod
        def decrypt(key=None, iv=None, data=None):
            return aes("ecb").decrypt(key, iv, data)

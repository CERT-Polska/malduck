# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from Crypto.PublicKey import RSA as RSA_

class RSA(object):
    def import_key(self, data):
        return RSA_.importKey(data).exportKey()

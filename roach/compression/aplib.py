# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach.native.aplib import unpack

class aPLib(object):
    def decompress(self, buf, length=None):
        return unpack(buf, length)

    __call__ = decompress

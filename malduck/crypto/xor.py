# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from Crypto.Cipher import XOR
from ..py2compat import is_integer, int2byte


def xor(key, data):
    if is_integer(key):
        key = int2byte(key)

    return XOR.new(key).decrypt(data)

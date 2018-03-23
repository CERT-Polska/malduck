# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import struct

def _worker(fmt, width, value):
    if isinstance(value, (int, long)):
        return struct.pack(fmt, value)

    count = len(value) / width
    ret = struct.unpack(fmt*count, value)
    return ret[0] if count == 1 else ret

def int16(value):
    return _worker("h", 2, value)

def uint16(value):
    return _worker("H", 2, value)

def int32(value):
    return _worker("i", 4, value)

def uint32(value):
    return _worker("I", 4, value)

def int64(value):
    return _worker("q", 8, value)

def uint64(value):
    return _worker("Q", 8, value)

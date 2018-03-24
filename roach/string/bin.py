# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import struct

from roach.string.ops import Padding

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

def bigint(s, bitsize):
    if isinstance(s, (int, long)):
        return Padding.null(("%x" % s).decode("hex")[::-1], bitsize / 8)

    if len(s) < bitsize / 8:
        return

    return int(s[:bitsize / 8][::-1].encode("hex"), 16)

# TODO Do we need any love on top of this?
unpack = struct.unpack
pack = struct.pack

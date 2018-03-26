# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import struct

from roach.string.ops import Padding

class IntWorker(object):
    fmt = None
    size = None

    def __init__(self, mul=None):
        self.mul = mul

    def __call__(self, value):
        if isinstance(value, (int, long)):
            return struct.pack(self.fmt, value)

        count = len(value) / self.size
        # TODO Should we return something else?
        if not count:
            return

        ret = struct.unpack(self.fmt*count, value)
        return ret[0] if count == 1 else ret

    def __mul__(self, other):
        """Helper method for roach.structure.Structure."""
        return self.__class__(other)

class Int8(IntWorker):
    fmt = "b"
    size = 1

class UInt8(IntWorker):
    fmt = "B"
    size = 1

class Int16(IntWorker):
    fmt = "h"
    size = 2

class UInt16(IntWorker):
    fmt = "H"
    size = 2

class Int32(IntWorker):
    fmt = "i"
    size = 4

class UInt32(IntWorker):
    fmt = "I"
    size = 4

class Int64(IntWorker):
    fmt = "q"
    size = 8

class UInt64(IntWorker):
    fmt = "Q"
    size = 8

int8 = Int8()
uint8 = UInt8()
int16 = Int16()
uint16 = UInt16()
int32 = Int32()
uint32 = UInt32()
int64 = Int64()
uint64 = UInt64()

def bigint(s, bitsize):
    if isinstance(s, (int, long)):
        return Padding.null(("%x" % s).decode("hex")[::-1], bitsize / 8)

    if len(s) < bitsize / 8:
        return

    return int(s[:bitsize / 8][::-1].encode("hex"), 16)

# TODO Do we need any love on top of this?
unpack = struct.unpack
pack = struct.pack

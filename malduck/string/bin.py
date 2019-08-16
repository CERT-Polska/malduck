# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.
import struct

from ..py2compat import is_integer
from ..string.ops import Padding, enhex, unhex
from ..ints import UInt8, UInt16, UInt32, UInt64, Int8, Int16, Int32, Int64


def bigint(s, bitsize):
    if is_integer(s):
        return Padding.null(unhex("%x" % s)[::-1], bitsize // 8)

    if len(s) < bitsize // 8:
        raise ValueError("Buffer is trimmed: {} < {}".format(len(s)*8, bitsize))

    return int(enhex(s[:bitsize // 8][::-1]), 16)


# Shortcuts for mostly used unpack methods
uint64 = u64 = UInt64.unpack
uint32 = u32 = UInt32.unpack
uint16 = u16 = UInt16.unpack
uint8 = u8 = UInt8.unpack

uint64be = u64be = UInt64.unpack_be
uint32be = u32be = UInt32.unpack_be
uint16be = u16be = UInt16.unpack_be
uint8be = u8be = UInt8.unpack_be

int64 = i64 = Int64.unpack
int32 = i32 = Int32.unpack
int16 = i16 = Int16.unpack
int8 = i8 = Int8.unpack

int64be = i64be = Int64.unpack_be
int32be = i32be = Int32.unpack_be
int16be = i16be = Int16.unpack_be
int8be = i8be = Int8.unpack_be


# Shortcuts for mostly used pack methods
p64 = lambda v: UInt64(v).pack()
p32 = lambda v: UInt32(v).pack()
p16 = lambda v: UInt16(v).pack()
p8 = lambda v: UInt8(v).pack()

p64be = lambda v: UInt64(v).pack_be()
p32be = lambda v: UInt32(v).pack_be()
p16be = lambda v: UInt16(v).pack_be()
p8be = lambda v: UInt8(v).pack_be()

unpack = struct.unpack
pack = struct.pack

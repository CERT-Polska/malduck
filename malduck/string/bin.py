# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/malduck.
# See the file 'docs/LICENSE.txt' for copying permission.

import struct

from ..string.ops import Padding, hex, unhex
from ..ints import UInt8, UInt16, UInt32, UInt64


def bigint(s, bitsize):
    if isinstance(s, (int, long)):
        return Padding.null(unhex("%x" % s)[::-1], bitsize / 8)

    if len(s) < bitsize / 8:
        return

    return int(hex(s[:bitsize / 8][::-1]), 16)


# Shortcuts for mostly used unpack methods
uint64 = u64 = UInt64.unpack
uint32 = u32 = UInt32.unpack
uint16 = u16 = UInt16.unpack
uint8 = u8 = UInt8.unpack

# Shortcuts for mostly used pack methods
p64 = lambda v: UInt64(v).pack()
p32 = lambda v: UInt32(v).pack()
p16 = lambda v: UInt16(v).pack()
p8 = lambda v: UInt8(v).pack()

unpack = struct.unpack
pack = struct.pack

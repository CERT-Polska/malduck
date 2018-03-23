# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import struct

def int16(s):
    return struct.unpack("h", s)[0]

def uint16(s):
    return struct.unpack("H", s)[0]

def int32(s):
    return struct.unpack("i", s)[0]

def uint32(s):
    return struct.unpack("I", s)[0]

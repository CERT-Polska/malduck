# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import zlib


def crc32(val):
    """
    Computes CRC32 checksum for provided data

    .. versionchanged:: 3.0.0
       Guaranteed to be unsigned on both Py2/Py3
    """
    return zlib.crc32(val) & 0xFFFFFFFF

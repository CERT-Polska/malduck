# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import zlib

__all__ = ["crc32"]


def crc32(val: bytes) -> int:
    """
    Computes CRC32 checksum for provided data
    """
    return zlib.crc32(val) & 0xFFFFFFFF

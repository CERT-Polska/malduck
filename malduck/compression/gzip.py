# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.
from __future__ import absolute_import

__all__ = ["gzip", "Gzip"]

from gzip import GzipFile
import io
import zlib


class Gzip:
    r"""
    gzip/zlib decompression

    .. code-block:: python

        from malduck import gzip, unhex

        # zlib decompression
        gzip(unhex(b'789ccb48cdc9c95728cf2fca4901001a0b045d'))
        # gzip decompression (detected by 1f8b08 prefix)
        gzip(unhex(b'1f8b08082199b75a0403312d3100cb48cdc9c95728cf2fca49010085114a0d0b000000'))

    :param buf: Buffer to decompress
    :type buf: bytes
    :rtype: bytes
    """

    def decompress(self, buf: bytes) -> bytes:
        if buf.startswith(b"\x1f\x8b\x08"):
            return GzipFile(fileobj=io.BytesIO(buf)).read()
        return zlib.decompress(buf)

    __call__ = decompress


gzip = Gzip()

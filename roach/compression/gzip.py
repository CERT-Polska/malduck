# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from __future__ import absolute_import

import gzip
import io
import zlib

class Gzip(object):
    def decompress(self, data):
        # TODO Is this non-strict enough (it's what Python's gzip accepts)?
        if data.startswith("\x1f\x8b\x08"):
            return gzip.GzipFile(fileobj=io.BytesIO(data)).read()
        return zlib.decompress(data)

    __call__ = decompress

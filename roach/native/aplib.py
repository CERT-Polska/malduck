# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import ctypes

from roach.native.common import load_library

try:
    aplib = load_library("aplib")
except ImportError as e:
    aplib = None

def unpack(buf, length=None):
    if not aplib:
        raise RuntimeError("aplib can't be used on your platform!")

    if not length:
        length = len(buf) * 2

    while True:
        out = ctypes.create_string_buffer(length)
        ret = aplib.aPsafe_depack(buf, len(buf), out, length)
        if ret > 0:
            break
        length *= 2

    return out.raw[:ret]

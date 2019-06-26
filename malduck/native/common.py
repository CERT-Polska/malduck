# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import ctypes
import os.path
import struct
import sys

components = os.path.join(os.path.dirname(__file__), "components")
is64bit = struct.calcsize("P") == 8

ext = {
    "win32": "dll",
    # py2
    "linux2": "so",
    "linux3": "so",
    # py3
    "linux": "so",
    "darwin": "dylib",
}[sys.platform]


def load_library(name, windows_calling_convention="windll"):
    filepath = os.path.join(
        components, "%s-%s.%s" % (name, 64 if is64bit else 32, ext)
    )
    if not os.path.exists(filepath):
        raise ImportError("Your platform is not supported!")

    if sys.platform == "win32":
        api = getattr(ctypes, windows_calling_convention)
    else:
        api = ctypes.cdll

    return api.LoadLibrary(filepath)

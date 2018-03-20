# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach import aplib

def test_aplib():
    assert aplib("".join(chr(int(_, 16)) for _ in """
41 50 33 32 18 00 00 00  0d 00 00 00 bc 9a 62 9b
0b 00 00 00 85 11 4a 0d  68 38 65 6c 8e 6f 20 77
6e 72 ec 64 00
""".split())) == "hello world"

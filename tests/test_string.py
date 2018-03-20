# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach import asciiz

def test_asciiz():
    assert asciiz("hello\x00world") == "hello"

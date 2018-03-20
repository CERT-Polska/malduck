# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach import asciiz, pad

def test_asciiz():
    assert asciiz("hello\x00world") == "hello"

def test_pad():
    assert pad("hello!!1", 8) == "hello!!1"
    assert pad("hello", 8) == "hello\x03\x03\x03"

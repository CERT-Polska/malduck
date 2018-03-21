# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach import asciiz, pad

def test_asciiz():
    assert asciiz("hello\x00world") == "hello"

def test_pad():
    assert pad("hello!!1", 8) == "hello!!1"
    assert pad("hello", 8) == "hello\x03\x03\x03"
    assert pad.pkcs7("hello!", 8) == "hello!\x02\x02"
    assert pad.null("hi", 4) == "hi\x00\x00"
    assert pad.null("foo_bar!", 8) == "foo_bar!"

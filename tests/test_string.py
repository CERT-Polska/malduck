# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach import asciiz, pad, ipv4, int16, uint16, int32, uint32

def test_asciiz():
    assert asciiz("hello\x00world") == "hello"

def test_pad():
    assert pad("hello!!1", 8) == "hello!!1"
    assert pad("hello", 8) == "hello\x03\x03\x03"
    assert pad.pkcs7("hello!", 8) == "hello!\x02\x02"
    assert pad.null("hi", 4) == "hi\x00\x00"
    assert pad.null("foo_bar!", 8) == "foo_bar!"

def test_ipv4():
    assert str(ipv4("ABCD")) == "65.66.67.68"

def test_bin():
    assert int16("AB") == 0x4241
    assert int16("\xff\xff") == -1
    assert uint16("AB") == 0x4241
    assert uint16("\xff\xff") == 0xffff

    assert int32("ABCD") == 0x44434241
    assert int32("\xff\xff\xff\xff") == -1
    assert uint32("ABCD") == 0x44434241
    assert uint32("\xff\xff\xff\xff") == 0xffffffff

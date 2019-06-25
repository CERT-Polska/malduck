# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from malduck import (
    uint8, uint16, uint32, uint64, bigint,
    p8, p16, p32, p64,
    asciiz, pad, unpad, ipv4, pack, unpack, hex, unhex, base64, uleb128,
    chunks, utf16z
)


def test_asciiz():
    assert asciiz("hello\x00world") == "hello"


def test_chunks():
    assert chunks("hello world", 3) == ["hel", "lo ", "wor", "ld"]


def test_utf16z():
    assert utf16z("h\x00e\x00l\x00l\x00o\x00\x00\x00world") == "h\x00e\x00l\x00l\x00o\x00"


def test_hex():
    assert hex("hello") == "68656c6c6f"
    assert unhex("68656c6c6f") == "hello"


def test_uleb128():
    assert uleb128("\x00") == (1, 0)
    assert uleb128("\xe5\x8e\x26") == (3, 624485)


def test_pad():
    assert pad("hello!!1", 8) == "hello!!1"
    assert pad("hello", 8) == "hello\x03\x03\x03"
    assert pad.pkcs7("hello!", 8) == "hello!\x02\x02"
    assert pad.null("hi", 4) == "hi\x00\x00"
    assert pad.null("foo_bar!", 8) == "foo_bar!"


def test_unpad():
    assert unpad("hello world!") == "hello world!"
    assert unpad("hello\x03\x03\x03") == "hello"
    assert unpad("hello\x02\x03\x03") == "hello\x02\x03\x03"


def test_base64():
    assert base64("aGVsbG8=") == "hello"
    assert base64("aGVsbG8=") == base64.decode("aGVsbG8=")
    assert base64.encode("hello") == "aGVsbG8="


def test_ipv4():
    assert str(ipv4("ABCD")) == "65.66.67.68"

    assert ipv4("ABC") is None
    assert bool(ipv4("ABC")) is False
    assert bool(ipv4("ABCD")) is True
    assert bool(ipv4("ABCDE")) is False
    assert bool(ipv4("1.2.3.4")) is True
    assert bool(ipv4("123.234.32.41")) is True
    assert bool(ipv4("323.234.32.41")) is False
    assert ipv4("1.2.3.4") == "1.2.3.4"
    assert ipv4("123.234.32.41") == "123.234.32.41"
    assert ipv4("255.255.255.255") == "255.255.255.255"

    assert ipv4("256.255.255.255") is None
    assert ipv4("255.256.255.255") is None
    assert ipv4("255.255.256.255") is None
    assert ipv4("255.255.255.256") is None

    assert ipv4(0x7f000001) == "127.0.0.1"


def test_bin():
    assert uint8("") is None
    assert uint8("B") == 0x42
    assert uint8("\xff") == 0xff

    assert uint16("A") is None
    assert uint16("AB") == 0x4241
    assert uint16("\xff\xff") == 0xffff

    assert uint32("ABC") is None
    assert uint32("ABCD") == 0x44434241
    assert uint32("\xff\xff\xff\xff") == 0xffffffff

    assert uint64("ABCDEFG") is None
    assert uint64("HGFEDCBA") == 0x4142434445464748
    assert uint64("\xff\xff\xff\xff\xff\xff\xff\xff") == 0xffffffffffffffff


def test_bin_reverse():
    assert p8(0x12) == "\x12"
    assert p8(0x34) == "\x34"
    assert p8(0xff) == "\xff"

    assert p16(0x5678) == "\x78\x56"
    assert p16(0xffff) == "\xff\xff"

    assert p32(0x87654321) == "\x21\x43\x65\x87"
    assert p32(0xffffffff) == "\xff\xff\xff\xff"

    assert p64(0x8877665544332211) == "\x11\x22\x33\x44\x55\x66\x77\x88"
    assert p64(0xffffffffffffffff) == "\xff\xff\xff\xff\xff\xff\xff\xff"


def test_bigint():
    assert bigint("ABCD", 40) is None
    assert bigint("ABCDE", 40) == 0x4544434241
    assert bigint(0x44434241, 40) == "ABCD\x00"


def test_pack():
    assert pack(
        "HHIQ", 0x4141, 0x4141, 0x41414141, 0x4141414141414141
    ) == "A"*16
    assert unpack("HHIQ", "A"*16) == (
        0x4141, 0x4141, 0x41414141, 0x4141414141414141
    )

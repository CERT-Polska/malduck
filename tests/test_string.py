# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import pytest

from malduck import (
    uint8, uint16, uint32, uint64, bigint,
    p8, p16, p32, p64,
    asciiz, pad, unpad, ipv4, pack, unpack, hex, unhex, base64, uleb128,
    chunks, utf16z
)


def test_asciiz():
    assert asciiz(b"hello\x00world") == b"hello"


def test_chunks():
    assert chunks(b"hello world", 3) == [b"hel", b"lo ", b"wor", b"ld"]


def test_utf16z():
    assert utf16z(b"h\x00e\x00l\x00l\x00o\x00\x00\x00world") == b"h\x00e\x00l\x00l\x00o\x00"


def test_hex():
    assert hex(b"hello") == b"68656c6c6f"
    assert unhex("68656c6c6f") == b"hello"


def test_uleb128():
    assert uleb128(b"\x00") == (1, 0)
    assert uleb128(b"\xe5\x8e\x26") == (3, 624485)


def test_pad():
    assert pad(b"hello!!1", 8) == b"hello!!1"
    assert pad(b"hello", 8) == b"hello\x03\x03\x03"
    assert pad.pkcs7(b"hello!", 8) == b"hello!\x02\x02"
    assert pad.null(b"hi", 4) == b"hi\x00\x00"
    assert pad.null(b"foo_bar!", 8) == b"foo_bar!"


def test_unpad():
    assert unpad(b"hello world!") == b"hello world!"
    assert unpad(b"hello\x03\x03\x03") == b"hello"
    assert unpad(b"hello\x02\x03\x03") == b"hello\x02\x03\x03"


def test_base64():
    assert base64("aGVsbG8=") == b"hello"
    assert base64("aGVsbG8=") == base64.decode("aGVsbG8=")
    assert base64.encode(b"hello") == b"aGVsbG8="


def test_ipv4():
    assert ipv4(b"ABCD") == "65.66.67.68"

    assert ipv4(b"ABC") is None
    assert bool(ipv4(b"ABC")) is False
    assert bool(ipv4(b"ABCD")) is True
    assert bool(ipv4(b"ABCDE")) is False
    assert bool(ipv4(b"1.2.3.4")) is True
    assert bool(ipv4(b"123.234.32.41")) is True
    assert bool(ipv4(b"323.234.32.41")) is False
    assert ipv4(b"1.2.3.4") == "1.2.3.4"
    assert ipv4(b"123.234.32.41") == "123.234.32.41"
    assert ipv4(b"255.255.255.255") == "255.255.255.255"

    assert ipv4(b"256.255.255.255") is None
    assert ipv4(b"255.256.255.255") is None
    assert ipv4(b"255.255.256.255") is None
    assert ipv4(b"255.255.255.256") is None

    assert ipv4(0x7f000001) == "127.0.0.1"


def test_bin():
    assert uint8(b"") is None
    assert uint8(b"B") == 0x42
    assert uint8(b"\xff") == 0xff

    assert uint16(b"A") is None
    assert uint16(b"AB") == 0x4241
    assert uint16(b"\xff\xff") == 0xffff

    assert uint32(b"ABC") is None
    assert uint32(b"ABCD") == 0x44434241
    assert uint32(b"\xff\xff\xff\xff") == 0xffffffff

    assert uint64(b"ABCDEFG") is None
    assert uint64(b"HGFEDCBA") == 0x4142434445464748
    assert uint64(b"\xff\xff\xff\xff\xff\xff\xff\xff") == 0xffffffffffffffff


def test_bin_reverse():
    assert p8(0x12) == b"\x12"
    assert p8(0x34) == b"\x34"
    assert p8(0xff) == b"\xff"

    assert p16(0x5678) == b"\x78\x56"
    assert p16(0xffff) == b"\xff\xff"

    assert p32(0x87654321) == b"\x21\x43\x65\x87"
    assert p32(0xffffffff) == b"\xff\xff\xff\xff"

    assert p64(0x8877665544332211) == b"\x11\x22\x33\x44\x55\x66\x77\x88"
    assert p64(0xffffffffffffffff) == b"\xff\xff\xff\xff\xff\xff\xff\xff"


def test_bigint():
    with pytest.raises(ValueError):
        bigint(b"ABCD", 40)
    assert bigint(b"ABCDE", 40) == 0x4544434241
    assert bigint(0x44434241, 40) == b"ABCD\x00"


def test_pack():
    assert pack(
        "HHIQ", 0x4141, 0x4141, 0x41414141, 0x4141414141414141
    ) == b"A"*16
    assert unpack("HHIQ", b"A"*16) == (
        0x4141, 0x4141, 0x41414141, 0x4141414141414141
    )

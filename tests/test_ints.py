from malduck import (
    Int8,
    Int16,
    Int32,
    Int64,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    p8,
    p16,
    p32,
    p64,
    u8,
    u16,
    u32,
    u64,
)


def test_int_like():
    """
    All IntTypes should behave like built-in int (long)
    """
    assert Int8("33") == 33
    assert Int8("-33") == -33
    assert UInt8("-2") == 254
    assert Int8(33) == 33
    assert Int8(1.5) == 1
    assert not Int8(0)
    assert Int8(-1) <= 0

    assert not u8(b"\x00")
    assert sorted([u16(b"\x00\x10"), u16(b"\x10\x00")]) == [0x10, 0x1000]

    assert [Int8(0x7F), Int16(0x7F), Int32(0x7F), Int64(0x7F),
            UInt8(0x7F), UInt16(0x7F), UInt32(0x7F), UInt64(0x7F)] == [0x7F]*8


def test_unsigned():
    assert UInt8(255) + 10 + 256 == 9
    n = UInt8(-1)
    n -= 1
    assert n == 254

    assert UInt16(0xF0F0) << 8 == 0xF000
    assert UInt16(0x4000) << 1 == 0x8000
    assert UInt64(0xFFFFFFFF) << 32 == 0xFFFFFFFF00000000
    assert UInt64(0xFFFFFFFF) << 48 == 0xFFFF000000000000
    assert UInt64(0xFFFFFFFF) >> 32 == 0
    assert UInt32(0xFFFFFFFF) << 32 == 0

    assert UInt8(-1) == 255
    assert UInt16(-1) == 65535
    assert UInt16(-1) * -1 == 1
    assert UInt16(-4) / 2 == UInt16(-4) >> 1
    assert UInt32(-65535) > UInt32(65535)

    assert UInt32(0x4444FFFF) << 16 | 0x8080 == 0xFFFF8080

    assert UInt8(UInt32(0xF0F0F0F0)) == 0xF0

    assert 255 + UInt8(1) == 256
    assert UInt8(255) + 1 == 0

    assert -UInt8(-1) == 1
    assert -UInt8(1) == UInt8(-1)

    assert ~UInt8(0xFF) == 0

    assert abs(UInt8(-1)) == UInt8(-1)

    assert p64(0x12345678) == b"\x78\x56\x34\x12\x00\x00\x00\x00"
    assert p32(0x12345678) == b"\x78\x56\x34\x12"
    assert p8(0x12345678) == b"\x78"

    assert p16(-1) == b"\xFF\xFF"
    assert p16(-32768) == b"\x00\x80"

    assert u32(b"\x78\x56\x34\x12") == 0x12345678

    assert u64(b"\x78\x56\x34\x12") is None


def test_signed():
    assert Int8(255) + 10 + 256 == 9
    assert Int8(255) - 10 == -11
    n = Int8(-1)
    n += 1
    assert n == 0

    assert Int16(0xF0F0) << 8 == -0x1000
    assert Int16(0x4000) << 1 == -0x8000

    assert Int8(-1) == -1
    assert Int16(-1) * -1 == 1
    assert Int16(-4) / 2 == -2
    assert Int32(-65535) < UInt32(65535)

    assert Int8(-128) - 1 == 127

    assert -Int8(-1) == 1
    assert -Int8(1) == -1

    assert abs(Int8(-1)) == Int8(1)

    assert ~Int8(0xFF) == 0


def test_rotate():
    assert UInt8(0b11100000).rol(3) == 0b00000111
    assert UInt8(0b11100011).rol(1) == 0b11000111

    assert UInt8(0b11100000).ror(3) == 0b00011100
    assert UInt8(0b11100011).ror(1) == 0b11110001


def test_multi_unpack():
    assert (UInt32 * 3).unpack(b"\x11\x22\x33\x44\xff\xff\xff\xff\x00\x00\x00\x00") == (0x44332211, 0xffffffff, 0)
    assert (Int32 * 3).unpack(b"\x11\x22\x33\x44\xff\xff\xff\xff\x00\x00\x00\x00") == (0x44332211, -1, 0)

    assert (UInt16 * 3).unpack(b"\x11\x22\x33\x44\xff\xff\xff\xff\x00\x00\x00\x00") == (0x2211, 0x4433, 0xffff)
    assert (Int16 * 3).unpack(b"\x11\x22\x33\x44\xff\xff\xff\xff\x00\x00\x00\x00") == (0x2211, 0x4433, -1)

    assert (UInt64 * 3).unpack(b"\x11\x22\x33\x44\xff\xff\xff\xff\x00\x00\x00\x00") is None
    assert (Int64 * 3).unpack(b"\x11\x22\x33\x44\xff\xff\xff\xff\x00\x00\x00\x00") is None


def test_fixed():
    assert type(UInt32.unpack(b'A'*16)) is UInt32
    assert type(UInt32.unpack(b'A'*16, fixed=False)) is int

    assert type((UInt32*4).unpack(b'A'*16)[0]) is UInt32
    assert type((UInt32*4).unpack(b'A'*16, fixed=False)[0]) is int  


def test_unpack_from():
    assert UInt32.unpack(b"\xAA\xAA\xF0\x0F\xF0\x0B\xAA", offset=2) == u32(b"\xF0\x0F\xF0\x0B")
    assert UInt32.unpack(b"\xAA\xAA\xF0\x0F\xF0\x0B", offset=2) == u32(b"\xF0\x0F\xF0\x0B")
    assert UInt32.unpack(b"\xAA\xAA\xF0\x0F\xF0", offset=2) is None

# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import pytest

from roach import (
    Structure, int8, uint8, int16, uint16, int32, uint32, int64, uint64
)

def test_structure():
    import ctypes

    class S1(Structure):
        _pack_ = 1
        _fields_ = [
            ("a", ctypes.c_ubyte),
            ("b", ctypes.c_ushort),
            ("c", ctypes.c_uint),
            ("d", ctypes.c_ubyte * 128),
        ]

    a = S1.from_buffer_copy("A"*135)
    assert a.a == 0x41
    assert a.b == 0x4141
    assert a.c == 0x41414141
    assert a.d[:] == [0x41] * 128
    assert a.as_dict() == {
        "a": 0x41,
        "b": 0x4141,
        "c": 0x41414141,
        "d": [0x41] * 128,
    }

    class S2(Structure):
        _pack_ = 1
        _fields_ = [
            ("a", S1),
            ("b", ctypes.c_ulonglong),
            ("c", ctypes.c_char * 32),
        ]

    a = S2.from_buffer_copy("A"*175)
    assert a.a.a == 0x41
    assert a.a.b == 0x4141
    assert a.a.c == 0x41414141
    assert a.a.d[:] == [0x41] * 128
    assert a.b == 0x4141414141414141
    assert a.c == "A"*32
    assert a.as_dict() == {
        "a": {
            "a": 0x41,
            "b": 0x4141,
            "c": 0x41414141,
            "d": [0x41] * 128,
        },
        "b": 0x4141414141414141,
        "c": "A"*32,
    }

    class S3(Structure):
        _pack_ = 1
        _fields_ = [
            ("a", S1),
            ("b", S2),
            ("c", ctypes.c_uint),
        ]

    a = S3.from_buffer_copy("B"*314)
    assert a.a.a == 0x42
    assert a.b.a.a == 0x42
    assert a.as_dict() == {
        "a": {
            "a": 0x42,
            "b": 0x4242,
            "c": 0x42424242,
            "d": [0x42] * 128,
        },
        "b": {
            "a": {
                "a": 0x42,
                "b": 0x4242,
                "c": 0x42424242,
                "d": [0x42] * 128,
            },
            "b": 0x4242424242424242,
            "c": "B"*32,
        },
        "c": 0x42424242,
    }

def test_int_wrappers():
    class I1(Structure):
        _fields_ = [
            ("a", int8),
            ("b", uint8),
            ("c", int16),
            ("d", uint16),
            ("e", int32),
            ("f", uint32),
            ("g", int64),
            ("h", uint64),
        ]

    a = I1.from_buffer_copy("A"*64)
    assert a.a == 0x41
    assert a.b == 0x41
    assert a.c == 0x4141
    assert a.d == 0x4141
    assert a.e == 0x41414141
    assert a.f == 0x41414141
    assert a.g == 0x4141414141414141
    assert a.h == 0x4141414141414141

    a = I1.from_buffer_copy("\xff"*64)
    assert a.a == -1
    assert a.b == 0xff
    assert a.c == -1
    assert a.d == 0xffff
    assert a.e == -1
    assert a.f == 0xffffffff
    assert a.g == -1
    assert a.h == 0xffffffffffffffff

    class I2(Structure):
        _fields_ = [
            ("i1", I1),
            ("a", uint32),
            ("b", int64),
        ]

    a = I2.from_buffer_copy("B"*76)
    assert a.i1.a == 0x42
    assert a.i1.h == 0x4242424242424242
    assert a.as_dict() == {
        "i1": {
            "a": 0x42,
            "b": 0x42,
            "c": 0x4242,
            "d": 0x4242,
            "e": 0x42424242,
            "f": 0x42424242,
            "g": 0x4242424242424242,
            "h": 0x4242424242424242,
        },
        "a": 0x42424242,
        "b": 0x4242424242424242,
    }

class test_multiply():
    class M(Structure):
        _fields_ = [
            ("a", uint8 * 8),
            ("b", uint32 * 4),
        ]

    m = M.parse("A"*8 + "B"*16)
    assert m.a[:] == [0x41] * 8

    # We can also omit the [:] part.
    assert m.b == [0x42424242] * 4

@pytest.mark.xfail
def test_nested_asdict():
    class I1(Structure):
        _fields_ = [
            ("a", int8),
            ("b", uint8),
            ("c", int16),
        ]

    class I2(Structure):
        _fields_ = [
            ("i1", I1),
            ("a", uint32),
        ]

    a = I2.from_buffer_copy("C"*8)

    # TODO It should be possible to call as_dict() on children of an Structure.
    assert a.i1.as_dict() == {
        "i1": {
            "a": 0x43,
            "b": 0x43,
            "c": 0x4343,
        },
        "a": 0x43434343,
    }

# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.
import struct
import warnings

from typing import Optional

from ..string.ops import Padding, enhex, unhex
from ..ints import UInt8, UInt16, UInt32, UInt64, Int8, Int16, Int32, Int64

__all__ = [
    "uint64",
    "uint32",
    "uint16",
    "uint8",
    "uint64be",
    "uint32be",
    "uint16be",
    "uint8be",
    "u64",
    "u32",
    "u16",
    "u8",
    "u64be",
    "u32be",
    "u16be",
    "u8be",
    "int64",
    "int32",
    "int16",
    "int8",
    "int64be",
    "int32be",
    "int16be",
    "int8be",
    "i64",
    "i32",
    "i16",
    "i8",
    "i64be",
    "i32be",
    "i16be",
    "i8be",
    "p64",
    "p32",
    "p16",
    "p8",
    "p64be",
    "p32be",
    "p16be",
    "p8be",
    "bigint",
    "unpack",
    "pack",
]


class Bigint:
    def unpack(self, other: bytes, size: Optional[int] = None) -> int:
        """
        Unpacks bigint value from provided buffer with little-endian order

        .. versionadded:: 4.0.0
            Use bigint.unpack instead of bigint() method

        :param other: Buffer object containing value to unpack
        :type other: bytes
        :param size: Size of bigint in bytes
        :type size: bytes, optional
        :rtype: int
        """
        if size:
            if len(other) < size:
                raise ValueError(f"Buffer is trimmed: {len(other)} < {size}")
            other = other[:size]
        return int(enhex(other[::-1]), 16)

    def pack(self, other: int, size: Optional[int] = None) -> bytes:
        """
        Packs bigint value into bytes with little-endian order

        .. versionadded:: 4.0.0
            Use bigint.pack instead of bigint() method

        :param other: Value to be packed
        :type other: int
        :param size: Size of bigint in bytes
        :type size: bytes, optional
        :rtype: bytes
        """
        packed = unhex(f"{other:x}")[::-1]
        if size:
            packed = packed[:size].ljust(size, b"\x00")
        return packed

    def unpack_be(self, other: bytes, size: Optional[int] = None) -> int:
        """
        Unpacks bigint value from provided buffer with big-endian order

        :param other: Buffer object containing value to unpack
        :type other: bytes
        :param size: Size of bigint in bytes
        :type size: bytes, optional
        :rtype: int
        """
        if size:
            if len(other) < size:
                raise ValueError(f"Buffer is trimmed: {len(other)} < {size}")
            other = other[:size]
        return int(enhex(other), 16)

    def pack_be(self, other: int, size: Optional[int] = None) -> bytes:
        """
        Packs bigint value into bytes with big-endian order

        .. versionadded:: 4.0.0
            Use bigint.pack instead of bigint() method

        :param other: Value to be packed
        :type other: int
        :param size: Size of bigint in bytes
        :type size: bytes, optional
        :rtype: bytes
        """
        packed = unhex(f"{other:x}")
        if size:
            packed = packed[:size].rjust(size, b"\x00")
        return packed

    def __call__(self, s, bitsize):
        warnings.warn(
            "malduck.bigint() is deprecated, use malduck.bigint.unpack/pack methods",
            DeprecationWarning,
        )
        if isinstance(s, int):
            return Padding.null(unhex("%x" % s)[::-1], bitsize // 8)

        if len(s) < bitsize // 8:
            raise ValueError(f"Buffer is trimmed: {len(s) * 8} < {bitsize}")

        return int(enhex(s[: bitsize // 8][::-1]), 16)


bigint = Bigint()

# Shortcuts for mostly used unpack methods
uint64 = u64 = UInt64.unpack
uint32 = u32 = UInt32.unpack
uint16 = u16 = UInt16.unpack
uint8 = u8 = UInt8.unpack

uint64be = u64be = UInt64.unpack_be
uint32be = u32be = UInt32.unpack_be
uint16be = u16be = UInt16.unpack_be
uint8be = u8be = UInt8.unpack_be

int64 = i64 = Int64.unpack
int32 = i32 = Int32.unpack
int16 = i16 = Int16.unpack
int8 = i8 = Int8.unpack

int64be = i64be = Int64.unpack_be
int32be = i32be = Int32.unpack_be
int16be = i16be = Int16.unpack_be
int8be = i8be = Int8.unpack_be


# Shortcuts for mostly used pack methods
def p64(v):
    return UInt64(v).pack()


def p32(v):
    return UInt32(v).pack()


def p16(v):
    return UInt16(v).pack()


def p8(v):
    return UInt8(v).pack()


def p64be(v):
    return UInt64(v).pack_be()


def p32be(v):
    return UInt32(v).pack_be()


def p16be(v):
    return UInt16(v).pack_be()


def p8be(v):
    return UInt8(v).pack_be()


unpack = struct.unpack
pack = struct.pack

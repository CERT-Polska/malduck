from abc import ABCMeta, abstractmethod
from struct import pack, unpack_from, error
from typing import (
    Any,
    Callable,
    Generic,
    Iterator,
    Optional,
    Union,
    Tuple,
    Type,
    TypeVar,
    cast,
)

from .bits import rol

__all__ = [
    "QWORD",
    "DWORD",
    "WORD",
    "BYTE",
    "CHAR",
    "UInt64",
    "UInt32",
    "UInt16",
    "UInt8",
    "Int64",
    "Int32",
    "Int16",
    "Int8",
]

T = TypeVar("T", bound="IntType")


class IntTypeBase(object):
    """
    Base class representing all IntType instances
    """

    pass


class MultipliedIntTypeBase(IntTypeBase, Generic[T], metaclass=ABCMeta):
    """
    Base class representing all MultipliedIntType instances
    """

    @staticmethod
    @abstractmethod
    def unpack(other: bytes, offset: int = 0) -> Optional[Tuple[T, ...]]:
        raise NotImplementedError()


class MetaIntType(type):
    """
    Metaclass for IntType classes.
    Provides ctypes-like behavior e.g. (QWORD*8).unpack(...) returns tuple of 8 QWORDs
    """

    bits: int
    signed: bool
    fmt: str

    @property
    def mask(cls) -> int:
        """
        Mask for potentially overflowing operations
        """
        return (2 ** cls.bits) - 1

    @property
    def invert_mask(cls) -> int:
        """
        Mask for sign bit
        """
        return (2 ** cls.bits) >> 1

    def __mul__(cls: Type[T], multiplier: int) -> Type[MultipliedIntTypeBase[T]]:  # type: ignore
        # mypy doesn't know how to deal with metaclasses
        # that are used for specific base class instantiation
        # We're doing our best, but 'type: ignore' is still needed here

        class MultipliedIntTypeClass(MultipliedIntTypeBase):
            int_type: Type[T] = cls
            mul = multiplier

            @staticmethod
            def unpack(other: bytes, offset: int = 0) -> Optional[Tuple[T, ...]]:
                """
                Unpacks multiple values from provided buffer
                :param other: Buffer object containing value to unpack
                :param offset: Buffer offset
                :return: tuple of IntType instances or None if there are not enough data to unpack
                """
                fmt = cls.fmt + cls.fmt[-1] * (multiplier - 1)
                try:
                    ret = unpack_from(fmt, other, offset=offset)
                except error:
                    return None
                ints: Iterator[T] = map(cls, ret)
                return tuple(ints)

        MultipliedIntTypeClass.__name__ = "Multiplied" + cls.__name__
        return MultipliedIntTypeClass


class IntType(int, IntTypeBase, metaclass=MetaIntType):
    """
    Fixed-size variant of int type with C-style operators and casting

    Supports ctypes-like multiplication for unpacking tuple of values

    * Unsigned types:
          :class:`UInt64` (:class:`QWORD`), :class:`UInt32` (:class:`DWORD`),
          :class:`UInt16` (:class:`WORD`), :class:`UInt8` (:class:`BYTE` or :class:`CHAR`)
    * Signed types:
          :class:`Int64`, :class:`Int32`, :class:`Int16`, :class:`Int8`

    IntTypes are derived from :class:`int` type, so they are fully compatible with other numeric types

    .. code-block:: python

        res = u32(0x8080FFFF) << 16 | 0xFFFF
        > 0xFFFFFFFF
        res = Int32(res)
        > -1

    Using IntTypes you don't need to mask everything with 0xFFFFFFFF, only if you remember about appropriate casting.

    .. code-block:: python

        from malduck import DWORD

        def rol7_hash(name: bytes):
            hh = 0
            for c in name:
                hh = DWORD(x).rol(7) ^ c
            return x

        def sdbm_hash(name: bytes):
            hh = 0
            for c in name:
                hh = DWORD(c) + (hh << 6) + (hh << 16) - hh
            return hh

    Type coercion between native and fixed integers depends on LHS type:

    .. code-block:: python

        UInt32 = UInt32 + int
        int = int + UInt32

    IntTypes can be multiplied like ctypes classes for unpacking tuple of values:

    .. code-block:: python

        values = (BYTE * 3).unpack('\\x01\\x02\\x03')

        values -> (1, 2, 3)
    """

    bits = 64
    signed = False
    fmt = "Q"

    def __new__(cls: MetaIntType, value: Any) -> "IntType":
        value = int(value) & cls.mask
        if cls.signed:
            value |= -(value & cls.invert_mask)
        construct = cast(Callable[[MetaIntType, Any], IntType], int.__new__)
        return construct(cls, value)

    def __add__(self, other: Any) -> "IntType":
        res = super().__add__(other)
        return self.__class__(res)

    def __sub__(self, other: Any) -> "IntType":
        res = super().__sub__(other)
        return self.__class__(res)

    def __mul__(self, other: Any) -> "IntType":
        res = super().__mul__(other)
        return self.__class__(res)

    def __truediv__(self, other: Any) -> "IntType":
        res = super().__truediv__(other)
        return self.__class__(res)

    def __floordiv__(self, other: Any) -> "IntType":
        res = super().__floordiv__(other)
        return self.__class__(res)

    def __and__(self, other: Any) -> "IntType":
        res = super().__and__(other)
        return self.__class__(res)

    def __xor__(self, other: Any) -> "IntType":
        res = super().__xor__(other)
        return self.__class__(res)

    def __or__(self, other: Any) -> "IntType":
        res = super().__or__(other)
        return self.__class__(res)

    def __lshift__(self, other: Any) -> "IntType":
        res = super().__lshift__(other)
        return self.__class__(res)

    def __pos__(self) -> "IntType":
        res = super().__pos__()
        return self.__class__(res)

    def __abs__(self) -> "IntType":
        res = super().__abs__()
        return self.__class__(res)

    def __rshift__(self, other: Any) -> "IntType":
        res = int.__rshift__(int(self) & self.__class__.mask, other)
        return self.__class__(res)

    def __neg__(self) -> "IntType":
        res = (int(self) ^ self.__class__.mask) + 1
        return self.__class__(res)

    def __invert__(self) -> "IntType":
        res = int(self) ^ self.__class__.mask
        return self.__class__(res)

    def rol(self, other) -> "IntType":
        """Bitwise rotate left"""
        return self.__class__(rol(int(self), other, bits=self.bits))

    def ror(self, other) -> "IntType":
        """Bitwise rotate right"""
        return self.rol(self.bits - other)

    def pack(self) -> bytes:
        """Pack value into bytes with little-endian order"""
        return pack("<" + self.fmt, int(self))

    def pack_be(self) -> bytes:
        """Pack value into bytes with big-endian order"""
        return pack(">" + self.fmt, int(self))

    @classmethod
    def unpack(
        cls, other: bytes, offset: int = 0, fixed: bool = True
    ) -> Union["IntType", int, None]:
        """
        Unpacks single value from provided buffer with little-endian order

        :param other: Buffer object containing value to unpack
        :type other: bytes
        :param offset: Buffer offset
        :type offset: int
        :param fixed: Convert to fixed-size integer (IntType instance)
        :type fixed: bool (default: True)
        :rtype: IntType instance or None if there are not enough data to unpack

        .. warning::
            Fixed-size integer operations are 4-5 times slower than equivalent on built-in integer types
        """
        try:
            ret = unpack_from("<" + cls.fmt, other, offset=offset)
        except error:
            return None
        return cls(ret[0]) if fixed else ret[0]

    @classmethod
    def unpack_be(
        cls, other: bytes, offset: int = 0, fixed: bool = True
    ) -> Union["IntType", int, None]:
        """
        Unpacks single value from provided buffer with big-endian order

        :param other: Buffer object containing value to unpack
        :type other: bytes
        :param offset: Buffer offset
        :type offset: int
        :param fixed: Convert to fixed-size integer (IntType instance)
        :type fixed: bool (default: True)
        :rtype: IntType instance or None if there are not enough data to unpack

        .. warning::
            Fixed-size integer operations are 4-5 times slower than equivalent on built-in integer types
        """
        try:
            ret = unpack_from(">" + cls.fmt, other, offset=offset)
        except error:
            return None
        return cls(ret[0]) if fixed else ret[0]


class UInt64(IntType):
    bits = 64
    signed = False
    fmt = "Q"


class UInt32(IntType):
    bits = 32
    signed = False
    fmt = "I"


class UInt16(IntType):
    bits = 16
    signed = False
    fmt = "H"


class UInt8(IntType):
    bits = 8
    signed = False
    fmt = "B"


class Int64(IntType):
    bits = 64
    signed = True
    fmt = "q"


class Int32(IntType):
    bits = 32
    signed = True
    fmt = "i"


class Int16(IntType):
    bits = 16
    signed = True
    fmt = "h"


class Int8(IntType):
    bits = 8
    signed = True
    fmt = "b"


QWORD = UInt64
DWORD = UInt32
WORD = UInt16
CHAR = BYTE = UInt8

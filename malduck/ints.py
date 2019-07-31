from struct import pack, unpack_from, error

from .bits import rol
from .py2compat import long, add_metaclass


class IntTypeBase(object):
    """
    Base class representing all IntType instances
    """
    pass


class MultipliedIntTypeBase(IntTypeBase):
    """
    Base class representing all MultipliedIntType instances
    """
    int_type = None
    mul = 0


class MetaIntType(type):
    """
    Metaclass for IntType classes.
    Provides ctypes-like behavior e.g. (QWORD*8).unpack(...) returns tuple of 8 QWORDs
    """
    @property
    def mask(cls):
        """
        Mask for potentially overflowing operations
        """
        return (2 ** cls.bits) - 1

    @property
    def invert_mask(cls):
        """
        Mask for sign bit
        """
        return (2 ** cls.bits) >> 1

    def __mul__(cls, multiplier):
        class MultipliedIntTypeClass(MultipliedIntTypeBase):
            int_type = cls
            mul = multiplier

            @staticmethod
            def unpack(other, offset=0):
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
                return tuple(map(cls, ret))

        MultipliedIntTypeClass.__name__ = "Multiplied" + cls.__name__
        return MultipliedIntTypeClass


@add_metaclass(MetaIntType)
class IntType(long, IntTypeBase):
    """
    Fixed-size variant of long type with C-style operators and casting

    Supports ctypes-like multiplication for unpacking tuple of values

    * Unsigned types:
          :class:`UInt64` (:class:`QWORD`), :class:`UInt32` (:class:`DWORD`),
          :class:`UInt16` (:class:`WORD`), :class:`UInt8` (:class:`BYTE` or :class:`CHAR`)
    * Signed types:
          :class:`Int64`, :class:`Int32`, :class:`Int16`, :class:`Int8`

    IntTypes are derived from :class:`long` type, so they are fully compatible with other numeric types

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
    fmt = "<Q"

    def __new__(cls, value):
        value = long(value) & cls.mask
        if cls.signed:
            value |= -(value & cls.invert_mask)
        return long.__new__(cls, value)

    def __add__(self, other):
        res = super(IntType, self).__add__(other)
        return self.__class__(res)

    def __sub__(self, other):
        res = super(IntType, self).__sub__(other)
        return self.__class__(res)

    def __mul__(self, other):
        res = super(IntType, self).__mul__(other)
        return self.__class__(res)

    def __div__(self, other):
        res = super(IntType, self).__div__(other)
        return self.__class__(res)

    def __truediv__(self, other):
        res = super(IntType, self).__truediv__(other)
        return self.__class__(res)

    def __floordiv__(self, other):
        res = super(IntType, self).__floordiv__(other)
        return self.__class__(res)

    def __and__(self, other):
        res = super(IntType, self).__and__(other)
        return self.__class__(res)

    def __xor__(self, other):
        res = super(IntType, self).__xor__(other)
        return self.__class__(res)

    def __or__(self, other):
        res = super(IntType, self).__or__(other)
        return self.__class__(res)

    def __lshift__(self, other):
        res = super(IntType, self).__lshift__(other)
        return self.__class__(res)

    def __pos__(self):
        res = super(IntType, self).__pos__()
        return self.__class__(res)

    def __abs__(self):
        res = super(IntType, self).__abs__()
        return self.__class__(res)

    def __rshift__(self, other):
        res = long.__rshift__(long(self) & self.__class__.mask, other)
        return self.__class__(res)

    def __neg__(self):
        res = (long(self) ^ self.__class__.mask) + 1
        return self.__class__(res)

    def __invert__(self):
        res = long(self) ^ self.__class__.mask
        return self.__class__(res)

    def rol(self, other):
        """Bitwise rotate left"""
        return self.__class__(rol(long(self), other, bits=self.bits))

    def ror(self, other):
        """Bitwise rotate right"""
        return self.rol(self.bits - other)

    def pack(self):
        """Pack value into bytes with little-endian order"""
        return pack(self.fmt, long(self))

    @classmethod
    def unpack(cls, other, offset=0, fixed=True):
        """
        Unpacks single value from provided buffer

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
            ret = unpack_from(cls.fmt, other, offset=offset)
        except error:
            return None
        return cls(ret[0]) if fixed else ret[0]


# Unsigned types

QWORD = UInt64 = type("UInt64", (IntType,), dict(bits=64, signed=False, fmt="<Q"))
DWORD = UInt32 = type("UInt32", (IntType,), dict(bits=32, signed=False, fmt="<I"))
WORD = UInt16 = type("UInt16", (IntType,), dict(bits=16, signed=False, fmt="<H"))
CHAR = BYTE = UInt8 = type("UInt8", (IntType,), dict(bits=8, signed=False, fmt="<B"))

# Signed types

Int64 = type("Int64", (IntType,), dict(bits=64, signed=True, fmt="<q"))
Int32 = type("Int32", (IntType,), dict(bits=32, signed=True, fmt="<i"))
Int16 = type("Int16", (IntType,), dict(bits=16, signed=True, fmt="<h"))
Int8 = type("Int8", (IntType,), dict(bits=8, signed=True, fmt="<b"))


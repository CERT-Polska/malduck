from struct import pack, unpack_from, error

from .bits import rol
from py2compat import long, add_metaclass


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
        return self.__class__(rol(long(self), other, bits=self.bits))

    def ror(self, other):
        return self.rol(self.bits - other)

    def pack(self):
        return pack(self.fmt, long(self))

    @classmethod
    def unpack(cls, other, offset=0):
        """
        Unpacks single value from provided buffer
        :param other: Buffer object containing value to unpack
        :param offset: Buffer offset
        :return: IntType instance or None if there are not enough data to unpack
        """
        try:
            ret = unpack_from(cls.fmt, other, offset=offset)
        except error:
            return None
        return cls(ret[0])


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


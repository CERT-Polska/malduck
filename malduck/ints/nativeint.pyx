#cython: language_level=3, overflowcheck=False

if (<unsigned long long> 0) - 1 != <unsigned long long>0xffffffffffffffff:
    raise ImportError("This module needs 2's complement architecture")

import ctypes
import os
from struct import error, pack, unpack_from

if os.getenv("MALDUCK_PYTHON_INTS") == "1":
    raise ImportError("Choosing legacy int implementation (MALDUCK_PYTHON_INTS)")


# bits
cpdef unsigned long long rol(unsigned long long value, int count, int bits = 32):
    """
    Bitwise rotate left

    :param value: Value to rotate
    :param count: Number of bits to rotate
    :param bits: Bit-length of rotated value (default: 32-bit, DWORD)
    """
    count = (bits - 1) & count
    value = (value << count) | (((<unsigned long long>1 << count) - 1) & (value >> (bits - count)))
    return value & ((<unsigned long long>(0) - 1) >> (64 - bits))


cdef unsigned long long convertToLong(value):
    """
    NativeInt constructor accepts "unsigned long long" directly to
    optimize object construction, crucial for operation performance.

    In the same time, we get OverflowError when negative or overflowing
    int is casted to "unsigned long long" so we need to mask it ourselves
    on initialization.
    """
    return value & 0xffffffffffffffff


FMT_MAPPING = {
    (64, False): "Q",
    (32, False): "I",
    (16, False): "H",
    (8, False): "B",
    (64, True): "q",
    (32, True): "i",
    (16, True): "h",
    (8, True): "b"
}

CTYPES_MAPPING = {
    (64, False): ctypes.c_ulonglong,
    (32, False): ctypes.c_uint,
    (16, False): ctypes.c_ushort,
    (8, False): ctypes.c_ubyte,
    (64, True): ctypes.c_longlong,
    (32, True): ctypes.c_int,
    (16, True): ctypes.c_short,
    (8, True): ctypes.c_byte,
}


cdef class FixedInt:
    cdef unsigned long long longval;
    cdef unsigned long long mask;
    cdef int bits;
    cdef bint sign;

    def __init__(self, unsigned long long value, int bits, bint sign):
        self.bits = bits
        # Make mask for 0xffff... as long as bitness
        self.mask = (<unsigned long long>(0) - 1) >> (64 - bits)
        # Mask the received value
        self.longval = value & self.mask
        # If signed: extend the sign bit to 64 bits
        if sign and value & <unsigned long long> (1 << (bits - 1)):
            self.longval |= (<unsigned long long>(0) - 1) << bits
        self.sign = sign

    cdef bint is_negative(self):
        return self.sign and self.longval & <unsigned long long> (1 << 63)

    cdef long long make_signed_longval(self):
        """
        Cython performs safety checks on unsigned -> signed casts
        FixedInt assumes two-complement architecture, but I don't see 
        if I can turn off these checks, so I need to make proper casting 
        myself. This is done only for operations where sign matters.
        """
        if self.longval & <unsigned long long> (1 << 63):
            return -<long long> (~self.longval + 1)
        else:
            return self.longval

    @property
    def _signval(self):
        # Exposes make_signed_longval for debug purposes
        return self.make_signed_longval()

    @property
    def _longval(self):
        # Exposes longval for debug purposes
        return self.longval

    @property
    def value(self):
        value = int(self.longval)
        if self.sign:
            invert_mask = 1 << (self.bits - 1)
            value |= -(self.longval & invert_mask)
        return value

    @property
    def typename(self):
        return f"{'' if self.sign else 'U'}Int{self.bits}"

    @property
    def struct_format(self):
        return FMT_MAPPING[(self.bits, self.sign)]

    def __add__(self, FixedInt other):
        # UInt64(2) + UInt64(2)
        return FixedInt(self.longval + other.longval, self.bits, self.sign)

    def __add__(self, long long other):
        # UInt64(2) + 2
        # This variant accepts immediate only within "signed long long" range
        # In other cases: convert argument to FixedInt first
        return FixedInt(self.longval + other, self.bits, self.sign)

    def __radd__(self, other):
        # 2 + UInt64(2)
        return other + self.value

    def __sub__(self, FixedInt other):
        # UInt64(2) - UInt64(2)
        return FixedInt(self.longval - other.longval, self.bits, self.sign)

    def __sub__(self, long long other):
        # UInt64(2) - UInt64(2)
        return FixedInt(self.longval - other, self.bits, self.sign)

    def __rsub__(self, other):
        # 2 - UInt64(2)
        return other - self.value

    def __mul__(self, FixedInt other):
        # UInt64(2) * UInt64(2)
        return FixedInt(self.longval * other.longval, self.bits, self.sign)

    def __mul__(self, long long other):
        # UInt64(2) * 2
        return FixedInt(self.longval * other, self.bits, self.sign)

    def __rmul__(self, other):
        # 2 * UInt64(2)
        return other * self.value

    def __floordiv__(self, FixedInt other):
        # UInt64(2) // UInt64(2)
        return FixedInt(self.longval // other.longval, self.bits, self.sign)

    def __floordiv__(self, long long other):
        # UInt64(2) // 2
        return FixedInt(self.longval // other, self.bits, self.sign)

    def __rfloordiv__(self, other):
        # 2 // UInt64(2)
        return other // self.value

    def __truediv__(self, FixedInt other):
        # UInt64(2) / UInt64(2)
        return self.value / other.value

    def __truediv__(self, long long other):
        # UInt64(2) / 2
        return self.value / other

    def __rtruediv__(self, other):
        # 2 / UInt64(2)
        return other / self.value

    def __mod__(self, FixedInt other):
        # UInt64(2) % UInt64(2)
        return FixedInt(self.longval % other.longval, self.bits, self.sign)

    def __mod__(self, long long other):
        # UInt64(2) % 2
        return FixedInt(self.longval % other, self.bits, self.sign)

    def __rmod__(self, other):
        # 2 % UInt64(2)
        return other % self.value

    def __pow__(self, FixedInt other):
        return FixedInt(self.longval ** other.longval, self.bits, self.sign)

    def __pow__(self, long long other):
        return FixedInt(self.longval ** other, self.bits, self.sign)

    def __rpow__(self, other):
        return other ** self.value

    def __neg__(self):
        return FixedInt((~self.longval) + 1, self.bits, self.sign)

    def __pos__(self):
        return self.value

    def __abs__(self):
        if self.sign:
            return FixedInt(abs(self.make_signed_longval()), self.bits, self.sign)
        else:
            return self

    def __bool__(self):
        return bool(self.longval)

    def __invert__(self):
        return FixedInt(~self.longval, self.bits, self.sign)

    def __lshift__(self, FixedInt other):
        return FixedInt(self.longval << other.longval, self.bits, self.sign)

    def __lshift__(self, unsigned long long other):
        return FixedInt(self.longval << other, self.bits, self.sign)

    def __rlshift__(self, other):
        return other << self.value

    def __rshift__(self, FixedInt other):
        # For signed numbers we need to perform proper sign extension
        cdef unsigned long long result = self.longval >> other.longval
        if self.sign & self.is_negative():
            result |= (<unsigned long long>(0) - 1) << (64 - other.longval)
            return FixedInt(result, self.bits, self.sign)
        else:
            return FixedInt(result, self.bits, self.sign)

    def __rshift__(self, unsigned long long other):
        # For signed numbers we need to perform proper sign extension
        cdef unsigned long long result = self.longval >> other
        if self.sign & self.is_negative():
            result |= (<unsigned long long>(0) - 1) << (64 - other)
            return FixedInt(result, self.bits, self.sign)
        else:
            return FixedInt(result, self.bits, self.sign)

    def __rrshift__(self, other):
        return other >> self.value

    def __and__(self, FixedInt other):
        return FixedInt(self.longval & other.longval, self.bits, self.sign)

    def __and__(self, unsigned long long other):
        return FixedInt(self.longval & other, self.bits, self.sign)

    def __rand__(self, other):
        return other & self.value

    def __xor__(self, FixedInt other):
        return FixedInt(self.longval ^ other.longval, self.bits, self.sign)

    def __xor__(self, unsigned long long other):
        return FixedInt(self.longval ^ other, self.bits, self.sign)

    def __rxor__(self, other):
        return other ^ self.value

    def __or__(self, FixedInt other):
        return FixedInt(self.longval | other.longval, self.bits, self.sign)

    def __or__(self, unsigned long long other):
        return FixedInt(self.longval | other, self.bits, self.sign)

    def __ror__(self, other):
        return other | self.value

    def __float__(self):
        return float(self.value)

    def __lt__(self, other):
        """self < other"""
        if type(other) is FixedInt:
            return self.value < other.value
        else:
            return self.value < other

    def __le__(self, other):
        """self <= other"""
        if type(other) is FixedInt:
            return self.value <= other.value
        else:
            return self.value <= other

    def __eq__(self, other):
        if type(other) is FixedInt:
            return self.value == other.value
        else:
            return self.value == other

    def __int__(self):
        # int(UInt64(2))
        return self.value

    def __index__(self):
        # int(UInt64(2)) used by conversions valid only for integrals
        return self.value

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return f"{self.typename}({self.value})"

    def __hash__(self):
        return hash(self.longval)

    @property
    def numerator(self):
        """Integers are their own numerators."""
        return self.value

    @property
    def denominator(self):
        """Integers have a denominator of 1."""
        return 1

    def pack(self):
        return pack("<" + self.struct_format, self.value)

    def pack_be(self):
        return pack(">" + self.struct_format, self.value)

    def rol(self, int other):
        return FixedInt(rol(self.longval, other, self.bits), self.bits, self.sign)

    def ror(self, int other):
        return FixedInt(rol(self.longval, self.bits - other, self.bits), self.bits, self.sign)

cdef class FixedIntType:
    cdef int bits
    cdef bint sign
    cdef public int multiplier

    def __init__(self, int bits, bint sign, int multiplier = 1):
        self.bits = bits
        self.sign = sign
        self.multiplier = multiplier

    @property
    def typename(self):
        return f"{'' if self.sign else 'U'}Int{self.bits}" \
               f"{' x '+str(self.multiplier) if self.multiplier > 1 else ''}"

    @property
    def struct_format(self):
        return FMT_MAPPING[(self.bits, self.sign)] * self.multiplier

    @property
    def ctypes_type(self):
        if self.multiplier == 1:
            return CTYPES_MAPPING[(self.bits, self.sign)]
        else:
            return CTYPES_MAPPING[(self.bits, self.sign)] * self.multiplier

    def __call__(self, value):
        return FixedInt(convertToLong(int(value)), self.bits, self.sign)

    def __mul__(self, int other):
        return FixedIntType(self.bits, self.sign, self.multiplier * other)

    def _unpack(self, fmt, other, offset, fixed):
        try:
            ret = unpack_from(fmt, other, offset=offset)
        except error:
            return None

        if not fixed:
            result = tuple(ret)
        else:
            nints = map(self.__call__, ret)
            result = tuple(nints)

        if self.multiplier > 1:
            return result
        else:
            return result[0]

    def unpack(self, other, offset = 0, fixed = True):
        return self._unpack("<" + self.struct_format, other, offset, fixed)

    def unpack_be(self, other, offset = 0, fixed = True):
        return self._unpack(">" + self.struct_format, other, offset, fixed)

    def __repr__(self):
        return f"<fixedinttype '{self.typename}'>"

    def __str__(self):
        return self.__repr__()


QWORD = UInt64 = FixedIntType(64, False)
DWORD = UInt32 = FixedIntType(32, False)
WORD = UInt16 = FixedIntType(16, False)
CHAR = BYTE = UInt8 = FixedIntType(8, False)
Int64 = FixedIntType(64, True)
Int32 = FixedIntType(32, True)
Int16 = FixedIntType(16, True)
Int8 = FixedIntType(8, True)

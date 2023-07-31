import ctypes
from struct import error, pack, unpack_from
from typing import Any

from malduck.bits import rol

FMT_MAPPING = {
    (64, False): "Q",
    (32, False): "I",
    (16, False): "H",
    (8, False): "B",
    (64, True): "q",
    (32, True): "i",
    (16, True): "h",
    (8, True): "b",
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


class FixedInt:
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

    def __init__(self, value, bits, sign):
        self.bits = bits
        self.sign = sign
        mask = (1 << bits) - 1
        value = int(value) & mask
        invert_mask = 1 << (self.bits - 1)
        if sign:
            value |= -(value & invert_mask)
        self.value = value

    @property
    def typename(self):
        return f"{'' if self.sign else 'U'}Int{self.bits}"

    @property
    def struct_format(self):
        return FMT_MAPPING[(self.bits, self.sign)]

    def __add__(self, other: Any) -> "FixedInt":
        return FixedInt(self.value + int(other), self.bits, self.sign)

    def __radd__(self, other: Any) -> int:
        return int(other) + self.value

    def __sub__(self, other: Any) -> "FixedInt":
        return FixedInt(self.value - int(other), self.bits, self.sign)

    def __rsub__(self, other: Any) -> int:
        return int(other) - self.value

    def __mul__(self, other: Any) -> "FixedInt":
        return FixedInt(self.value * int(other), self.bits, self.sign)

    def __rmul__(self, other: Any) -> int:
        return int(other) * self.value

    def __floordiv__(self, other: Any) -> "FixedInt":
        return FixedInt(self.value // int(other), self.bits, self.sign)

    def __rfloordiv__(self, other: Any) -> int:
        return int(other) // self.value

    def __truediv__(self, other: Any) -> float:
        return self.value / int(other)

    def __rtruediv__(self, other: Any) -> float:
        return int(other) / self.value

    def __mod__(self, other: Any) -> "FixedInt":
        return FixedInt(self.value % int(other), self.bits, self.sign)

    def __rmod__(self, other: Any) -> int:
        return int(other) % self.value

    def __pow__(self, other) -> "FixedInt":
        return FixedInt(self.value ** int(other), self.bits, self.sign)

    def __rpow__(self, other) -> int:
        return int(other) ** self.value

    def __neg__(self) -> "FixedInt":
        return FixedInt(-self.value, self.bits, self.sign)

    def __pos__(self) -> int:
        return self.value

    def __abs__(self) -> "FixedInt":
        return FixedInt(abs(self.value), self.bits, self.sign)

    def __bool__(self) -> bool:
        return bool(self.value)

    def __invert__(self) -> "FixedInt":
        return FixedInt(~self.value, self.bits, self.sign)

    def __lshift__(self, other: Any) -> "FixedInt":
        return FixedInt(self.value << int(other), self.bits, self.sign)

    def __rlshift__(self, other: Any) -> int:
        return int(other) << self.value

    def __rshift__(self, other: Any) -> "FixedInt":
        return FixedInt(self.value >> int(other), self.bits, self.sign)

    def __rrshift__(self, other: Any) -> int:
        return int(other) >> self.value

    def __and__(self, other: Any) -> "FixedInt":
        return FixedInt(self.value & int(other), self.bits, self.sign)

    def __rand__(self, other: Any) -> int:
        return int(other) & self.value

    def __xor__(self, other: Any) -> "FixedInt":
        return FixedInt(self.value ^ int(other), self.bits, self.sign)

    def __rxor__(self, other: Any) -> int:
        return int(other) ^ self.value

    def __or__(self, other: Any) -> "FixedInt":
        return FixedInt(self.value | int(other), self.bits, self.sign)

    def __ror__(self, other: Any) -> int:
        return int(other) | self.value

    def __float__(self) -> float:
        return float(self.value)

    def __lt__(self, other: Any) -> bool:
        return self.value < int(other)

    def __le__(self, other: Any) -> bool:
        return self.value <= int(other)

    def __eq__(self, other: Any) -> bool:
        return self.value == int(other)

    def __int__(self) -> int:
        return self.value

    def __index__(self) -> int:
        # int(UInt64(2)) used by conversions valid only for integrals
        return self.value

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return f"{self.typename}({self.value})"

    def __hash__(self) -> int:
        return hash(self.value)

    @property
    def numerator(self) -> int:
        """Integers are their own numerators."""
        return self.value

    @property
    def denominator(self) -> int:
        """Integers have a denominator of 1."""
        return 1

    def pack(self) -> bytes:
        return pack("<" + self.struct_format, self.value)

    def pack_be(self) -> bytes:
        return pack(">" + self.struct_format, self.value)

    def rol(self, other: Any) -> "FixedInt":
        return FixedInt(rol(self.value, other, self.bits), self.bits, self.sign)

    def ror(self, other: Any) -> "FixedInt":
        return FixedInt(
            rol(self.value, self.bits - other, self.bits), self.bits, self.sign
        )


class FixedIntType:
    def __init__(self, bits: int, sign: bool, multiplier: int = 1):
        self.bits = bits
        self.sign = sign
        self.multiplier = multiplier

    @property
    def typename(self):
        return (
            f"{'' if self.sign else 'U'}Int{self.bits}"
            f"{' x '+str(self.multiplier) if self.multiplier > 1 else ''}"
        )

    @property
    def struct_format(self):
        return FMT_MAPPING[(self.bits, self.sign)] * self.multiplier

    @property
    def ctypes_type(self):
        if self.multiplier == 1:
            return CTYPES_MAPPING[(self.bits, self.sign)]
        else:
            return CTYPES_MAPPING[(self.bits, self.sign)] * self.multiplier

    def __call__(self, value: int) -> FixedInt:
        return FixedInt(value, self.bits, self.sign)

    def __mul__(self, other: int) -> "FixedIntType":
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

    def unpack(self, other, offset=0, fixed=True):
        return self._unpack("<" + self.struct_format, other, offset, fixed)

    def unpack_be(self, other, offset=0, fixed=True):
        return self._unpack(">" + self.struct_format, other, offset, fixed)

    def __repr__(self) -> str:
        return f"<fixedinttype '{self.typename}'>"

    def __str__(self) -> str:
        return self.__repr__()


QWORD = UInt64 = FixedIntType(64, False)
DWORD = UInt32 = FixedIntType(32, False)
WORD = UInt16 = FixedIntType(16, False)
CHAR = BYTE = UInt8 = FixedIntType(8, False)
Int64 = FixedIntType(64, True)
Int32 = FixedIntType(32, True)
Int16 = FixedIntType(16, True)
Int8 = FixedIntType(8, True)

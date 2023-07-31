from .native.ints import (
    BYTE,
    CHAR,
    DWORD,
    NATIVE_INT,
    QWORD,
    WORD,
    FixedInt,
    FixedIntType,
    Int8,
    Int16,
    Int32,
    Int64,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
)


def is_native_impl() -> bool:
    return NATIVE_INT


__all__ = [
    "BYTE",
    "CHAR",
    "DWORD",
    "QWORD",
    "WORD",
    "FixedInt",
    "FixedIntType",
    "Int8",
    "Int16",
    "Int32",
    "Int64",
    "UInt8",
    "UInt16",
    "UInt32",
    "UInt64",
    "NATIVE_INT",
]

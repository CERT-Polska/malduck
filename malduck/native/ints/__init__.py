try:
    from .nativeint import (
        BYTE,
        CHAR,
        DWORD,
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

    NATIVE_INT = True
except ImportError as e:
    import warnings

    warnings.warn(
        f"Falling back to Python legacy implementation of malduck.ints: {str(e)}",
        UserWarning,
    )
    from .pyint import (
        BYTE,
        CHAR,
        DWORD,
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

    NATIVE_INT = False


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
    "FixedInt",
    "FixedIntType",
    "NATIVE_INT",
]

# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from base64 import b64decode, b64encode
from typing import Iterator, List, Optional, Sequence, Union, Tuple, TypeVar, cast

import binascii

__all__ = [
    "asciiz",
    "chunks_iter",
    "chunks",
    "utf16z",
    "enhex",
    "unhex",
    "uleb128",
    "Base64",
    "Padding",
    "Unpadding",
    "base64",
    "pad",
    "pkcs7",
    "unpad",
    "unpkcs7",
]

T = TypeVar("T", bound=Sequence)


def asciiz(s: bytes) -> bytes:
    """
    Treats s as null-terminated ASCII string

    :param s: Buffer containing null-terminated ASCII string
    :type s: bytes
    """
    return s.split(b"\x00")[0]


def chunks_iter(s: T, n: int) -> Iterator[T]:
    """Yield successive n-sized chunks from s."""
    return (cast(T, s[i : i + n]) for i in range(0, len(s), n))


def chunks(s: T, n: int) -> List[T]:
    """Return list of successive n-sized chunks from s."""
    return list(chunks_iter(s, n))


def utf16z(s: bytes) -> bytes:
    """
    Treats s as null-terminated UTF-16 ASCII string

    :param s: Buffer containing null-terminated UTF-16 string
    :type s: bytes
    :return: ASCII string without '\x00' terminator
    :rtype: bytes
    """
    chunked = chunks(s, 2)
    if b"\x00\x00" in chunked:
        return (
            s[: chunked.index(b"\x00\x00") * 2]
            .decode("utf-16")
            .rstrip("\x00")
            .encode("ascii")
        )
    return s


def enhex(s: bytes) -> bytes:
    """
    .. versionchanged:: 2.0.0

        Renamed from :py:meth:`malduck.hex`
    """
    return binascii.hexlify(s)


def unhex(s: Union[str, bytes]) -> bytes:
    return binascii.unhexlify(s)


def uleb128(s: bytes) -> Optional[Tuple[int, int]]:
    """Unsigned Little-Endian Base 128"""
    ret = 0
    for idx in range(len(s)):
        ret += (s[idx] & 0x7F) << (idx * 7)
        if s[idx] < 0x80:
            break
    else:
        return None
    return idx + 1, ret


class Base64:
    """Base64 encoder/decoder"""

    def encode(self, s: bytes) -> bytes:
        return b64encode(s)

    def decode(self, s: Union[str, bytes]) -> bytes:
        return b64decode(s)

    __call__ = decode


class Padding:
    """
    Padding PKCS7/NULL
    """

    def __init__(self, style: str) -> None:
        self.style = style

    @staticmethod
    def null(s: bytes, block_size: int) -> bytes:
        return Padding("null").pad(s, block_size)

    def pad(self, s: bytes, block_size: int) -> bytes:
        length = block_size - len(s) % block_size
        if length == block_size:
            padding = b""
        elif self.style == "pkcs7":
            padding = bytes([length]) * length
        elif self.style == "null":
            padding = b"\x00" * length
        else:
            raise ValueError(f"Unknown padding {self.style}")
        return s + padding

    __call__ = pkcs7 = pad


class Unpadding:
    """
    Unpadding PKCS7/NULL
    """

    def __init__(self, style: str) -> None:
        self.style = style

    def unpad(self, s: bytes) -> bytes:
        count = s[-1] if s else 0
        if self.style == "pkcs7" and s[-count:] == bytes([s[-1]]) * count:
            return s[:-count]
        return s

    __call__ = pkcs7 = unpad


base64 = Base64()
pad = Padding("pkcs7")
pkcs7 = Padding("pkcs7")
unpad = Unpadding("pkcs7")
unpkcs7 = Unpadding("pkcs7")

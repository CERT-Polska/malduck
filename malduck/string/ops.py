# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import base64
import binascii

from ..py2compat import indexbytes, int2byte


def asciiz(s):
    """
    Treats s as null-terminated ASCII string

    :param s: Buffer containing null-terminated ASCII string
    :type s: bytes
    """
    return s.split(b"\x00")[0]


def chunks_iter(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def chunks(l, n):
    """Return list of successive n-sized chunks from l."""
    return list(chunks_iter(l, n))


def utf16z(s):
    """
    Treats s as null-terminated UTF-16 ASCII string

    :param s: Buffer containing null-terminated UTF-16 string
    :type s: bytes
    :return: ASCII string without '\x00' terminator
    :rtype: bytes
    """
    chunked = chunks(s, 2)
    if b'\x00\x00' in chunked:
        return s[:chunked.index(b'\x00\x00')*2].decode("utf-16").rstrip("\x00").encode("ascii")
    return s


def enhex(s):
    """
    .. versionchanged:: 2.0.0

        Renamed from :py:meth:`malduck.hex`
    """
    return binascii.hexlify(s)


def unhex(s):
    return binascii.unhexlify(s)


def uleb128(s):
    """Unsigned Little-Endian Base 128"""
    ret = 0
    for idx in range(len(s)):
        ret += (indexbytes(s, idx) & 0x7f) << (idx*7)
        if indexbytes(s, idx) < 0x80:
            break
    else:
        return None
    return idx + 1, ret


class Base64(object):
    """Base64 encoder/decoder"""
    def encode(self, s):
        return base64.b64encode(s)

    def decode(self, s):
        return base64.b64decode(s)

    __call__ = decode


class Padding(object):
    """
    Padding PKCS7/NULL
    """
    def __init__(self, style):
        self.style = style

    @staticmethod
    def null(s, block_size):
        return Padding("null").pad(s, block_size)

    def pad(self, s, block_size):
        length = block_size - len(s) % block_size
        if length == block_size:
            padding = b""
        elif self.style == "pkcs7":
            padding = int2byte(length) * length
        elif self.style == "null":
            padding = b"\x00" * length
        else:
            raise ValueError("Unknown padding {}".format(self.style))
        return s + padding

    __call__ = pkcs7 = pad


class Unpadding(object):
    """
    Unpadding PKCS7/NULL
    """
    def __init__(self, style):
        self.style = style

    def unpad(self, s):
        count = indexbytes(s, -1) if s else 0
        if self.style == "pkcs7" and s[-count:] == int2byte(indexbytes(s, -1)) * count:
            return s[:-count]
        return s

    __call__ = pkcs7 = unpad

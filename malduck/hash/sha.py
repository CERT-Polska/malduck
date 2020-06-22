# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import hashlib

__all__ = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]


def md5(s: bytes) -> bytes:
    return hashlib.md5(s).digest()


def sha1(s: bytes) -> bytes:
    return hashlib.sha1(s).digest()


def sha224(s: bytes) -> bytes:
    return hashlib.sha224(s).digest()


def sha256(s: bytes) -> bytes:
    return hashlib.sha256(s).digest()


def sha384(s: bytes) -> bytes:
    return hashlib.sha384(s).digest()


def sha512(s: bytes) -> bytes:
    return hashlib.sha512(s).digest()

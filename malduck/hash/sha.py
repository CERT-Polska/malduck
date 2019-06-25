# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import hashlib


def md5(s):
    return hashlib.md5(s).digest()


def sha1(s):
    return hashlib.sha1(s).digest()


def sha224(s):
    return hashlib.sha224(s).digest()


def sha256(s):
    return hashlib.sha256(s).digest()


def sha384(s):
    return hashlib.sha384(s).digest()


def sha512(s):
    return hashlib.sha512(s).digest()

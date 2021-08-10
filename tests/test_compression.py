# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import pytest

from malduck import aplib, gzip, base64, lznt1


def test_aplib():
    assert aplib(
        base64("QVAzMhgAAAANAAAAvJpimwsAAACFEUoNaDhlbI5vIHducuxkAA==")
    ) == b"hello world"
    assert aplib(base64("aDhlbI5vIHducuxkAA==")) == b"hello world"
    assert aplib(base64("""
QVAzMhgAAABGAAAAf+p8HwEAEAA5iu7QQacB19//yAF9ff/8hwHX3//IAX19//yHAdff/8gBfX3/
/IcB19//yAF9ff/8hwHX3//IAX19//yHAdff/8gBXXf/2QqAAA==
""")) == b"A"*1024*1024 + b"\n"
    assert aplib(base64("""
QacB19//yAF9ff/8hwHX3//IAX19//yHAdff/8gBfX3//IcB19//yAF9ff/
8hwHX3//IAX19//yH\nAdff/8gBXXf/2QqAAA==
""")) == b"A"*1024*1024 + b"\n"
    assert (
        aplib(b'T\x00he quick\xecb\x0erown\xcef\xaex\x80jumps\xed\xe4veur`t?lazy\xead\xfeg\xc0\x00') ==
        b'The quick brown fox jumps over the lazy dog')


def test_gzip():
    assert gzip(base64("eJzLSM3JyVcozy/KSQEAGgsEXQ==")) == b"hello world"
    assert gzip(
        base64("H4sICCGZt1oEAzEtMQDLSM3JyVcozy/KSQEAhRFKDQsAAAA=")
    ) == b"hello world"
    assert gzip(
        base64("H4sICCOZt1oCAzEtOQDLSM3JyVcozy/KSQEAhRFKDQsAAAA=")
    ) == b"hello world"


def test_lznt1():
    assert lznt1(b"\x1a\xb0\x00compress\x00edtestda\x04ta\x07\x88alot") == b"compressedtestdatacompressedalot"

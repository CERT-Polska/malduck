# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import pytest

from roach import aplib, gzip, base64

@pytest.mark.skipif("sys.platform == 'darwin'")
def test_aplib():
    assert aplib(
        base64("QVAzMhgAAAANAAAAvJpimwsAAACFEUoNaDhlbI5vIHducuxkAA==")
    ) == "hello world"
    assert aplib(base64("aDhlbI5vIHducuxkAA==")) == "hello world"

    assert aplib(base64("""
QVAzMhgAAABGAAAAf+p8HwEAEAA5iu7QQacB19//yAF9ff/8hwHX3//IAX19//yHAdff/8gBfX3/
/IcB19//yAF9ff/8hwHX3//IAX19//yHAdff/8gBXXf/2QqAAA==
""")) == "A"*1024*1024 + "\n"
    assert aplib(base64("""
QacB19//yAF9ff/8hwHX3//IAX19//yHAdff/8gBfX3//IcB19//yAF9ff/
8hwHX3//IAX19//yH\nAdff/8gBXXf/2QqAAA==
""")) == "A"*1024*1024 + "\n"

    assert aplib("helloworld") is None

@pytest.mark.skipif("sys.platform != 'darwin'")
def test_aplib_macos():
    with pytest.raises(RuntimeError):
        assert aplib("hello world")

def test_gzip():
    assert gzip(base64("eJzLSM3JyVcozy/KSQEAGgsEXQ==")) == "hello world"
    assert gzip(
        base64("H4sICCGZt1oEAzEtMQDLSM3JyVcozy/KSQEAhRFKDQsAAAA=")
    ) == "hello world"
    assert gzip(
        base64("H4sICCOZt1oCAzEtOQDLSM3JyVcozy/KSQEAhRFKDQsAAAA=")
    ) == "hello world"

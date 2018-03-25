# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach import aplib, gzip

def test_aplib():
    assert aplib(
        "QVAzMhgAAAANAAAAvJpimwsAAACFEUoNaDhlbI5vIHducuxkAA==".decode("base64")
    ) == "hello world"
    assert aplib(
        "aDhlbI5vIHducuxkAA==".decode("base64")
    ) == "hello world"

    assert aplib("""
QVAzMhgAAABGAAAAf+p8HwEAEAA5iu7QQacB19//yAF9ff/8hwHX3//IAX19//yHAdff/8gBfX3/
/IcB19//yAF9ff/8hwHX3//IAX19//yHAdff/8gBXXf/2QqAAA==
""".strip().decode("base64")) == "A"*1024*1024 + "\n"
    assert aplib("""
QacB19//yAF9ff/8hwHX3//IAX19//yHAdff/8gBfX3//IcB19//yAF9ff/
8hwHX3//IAX19//yH\nAdff/8gBXXf/2QqAAA==
""".decode("base64")) == "A"*1024*1024 + "\n"

    assert aplib("helloworld") is None

def test_gzip():
    assert gzip(
        "eJzLSM3JyVcozy/KSQEAGgsEXQ==".decode("base64")
    ) == "hello world"
    assert gzip(
        "H4sICCGZt1oEAzEtMQDLSM3JyVcozy/KSQEAhRFKDQsAAAA=".decode("base64")
    ) == "hello world"
    assert gzip(
        "H4sICCOZt1oCAzEtOQDLSM3JyVcozy/KSQEAhRFKDQsAAAA=".decode("base64")
    ) == "hello world"

# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from malduck import verify


def test_ascii():
    assert verify.ascii(b"hello world") is True
    assert verify.ascii(b"foobar\x00") is False


def test_domain():
    assert verify.domain(b"apple.com") is True
    assert verify.domain(b"http://google.com") is False
    assert verify.domain(b":\xb4\xa1") is False


def test_url():
    assert verify.url(b"apple.com") is False
    assert verify.url(b"http://google.com") is True
    assert verify.url(b"http://bing.com/") is True
    assert verify.url(b":\xb4\xa1") is False

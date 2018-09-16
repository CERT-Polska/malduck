# Copyright (C) 2018 Jurriaan Bremer.
# Copyright (C) 2018 Hatching B.V.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach import verify

def test_ascii():
    assert verify.ascii("hello world") is True
    assert verify.ascii("foobar\x00") is False

def test_domain():
    assert verify.domain("apple.com") is True
    assert verify.domain("http://google.com") is False
    assert verify.domain(":\xb4\xa1") is False

def test_url():
    assert verify.url("apple.com") is False
    assert verify.url("http://google.com") is True
    assert verify.url("http://bing.com/") is True
    assert verify.url(":\xb4\xa1") is False

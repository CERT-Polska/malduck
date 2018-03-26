# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach import verify

def test_ascii():
    assert verify.ascii("hello world") is True
    assert verify.ascii("foobar\x00") is False

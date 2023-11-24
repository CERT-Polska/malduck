# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from malduck import align, align_down, rol, ror


def test_rotate():
    assert rol(0b11100000, 3, 8) == 0b00000111
    assert rol(0b11100011, 1, 8) == 0b11000111

    assert ror(0b11100000, 3, 8) == 0b00011100
    assert ror(0b11100011, 1, 8) == 0b11110001


def test_overrotate():
    assert rol(0b11100000, 19, 8) == 0b00000111
    assert rol(0b11100011, 17, 8) == 0b11000111

    assert ror(0b11100000, 11, 8) == 0b00011100
    assert ror(0b11100011, 10, 8) == 0b11111000


def test_align():
    assert align(0, 0x1000) == 0
    assert align(1, 0x1000) == 0x1000
    assert align(0xfff, 0x1000) == 0x1000
    assert align(0x1000, 0x1000) == 0x1000
    assert align(0x1001, 0x1000) == 0x2000

    assert align_down(0, 0x1000) == 0
    assert align_down(1, 0x1000) == 0
    assert align_down(0xfff, 0x1000) == 0
    assert align_down(0x1000, 0x1000) == 0x1000
    assert align_down(0x1001, 0x1000) == 0x1000

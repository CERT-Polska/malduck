# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach import rol, ror

def test_rotate():
    assert rol(0b11100000, 3, 8) == 0b00000111
    assert rol(0b11100011, 1, 8) == 0b11000111

    assert ror(0b11100000, 3, 8) == 0b00011100
    assert ror(0b11100011, 1, 8) == 0b11110001

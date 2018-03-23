# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

def rol(value, count, bits=32):
    count = (bits - 1) & count
    value = (value << count) | ((2**count - 1) & (value >> (bits - count)))
    return value % 2**bits

def ror(value, count, bits=32):
    return rol(value, bits - count, bits)

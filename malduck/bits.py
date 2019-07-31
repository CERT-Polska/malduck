# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.


def rol(value, count, bits=32):
    """
    Bitwise rotate left
    :param value: Value to rotate
    :param count: Number of bits to rotate
    :param bits: Bit-length of rotated value (default: 32-bit, DWORD)

    .. seealso::

       :py:meth:`malduck.ints.IntType.rol`

    """
    count = (bits - 1) & count
    value = (value << count) | ((2**count - 1) & (value >> (bits - count)))
    return value % 2**bits


def ror(value, count, bits=32):
    """
    Bitwise rotate right
    :param value: Value to rotate
    :param count: Number of bits to rotate
    :param bits: Bit-length of rotated value (default: 32-bit, DWORD)

    .. seealso::

       :py:meth:`malduck.ints.IntType.ror`

    """
    return rol(value, bits - count, bits)


def align(value, round_to):
    """
    Rounds value up to provided alignment
    """
    return ((value - 1) // round_to + 1) * round_to


def align_down(value, round_to):
    """
    Rounds value down to provided alignment
    """
    return (value // round_to) * round_to

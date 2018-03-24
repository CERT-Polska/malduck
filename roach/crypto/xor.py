# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

def xor(a, b):
    if not isinstance(a, basestring):
        raise RuntimeError("first xor value must be a string!")

    if isinstance(b, (int, long)):
        b = chr(b)

    return "".join(
        chr(ord(a[x % len(a)]) ^ ord(b[x % len(b)])) for x in xrange(len(a))
    )

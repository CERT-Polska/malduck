# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

def xor(key, data):
    if not isinstance(data, basestring):
        raise RuntimeError("data value must be a string!")

    if isinstance(key, (int, long)):
        key = chr(key)

    return "".join(
        chr(ord(data[x]) ^ ord(key[x % len(key)])) for x in xrange(len(data))
    )

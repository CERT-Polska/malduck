# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach.crypto.aes import AES
from roach.short import aes

def test_aes128cbc():
    assert AES("A"*16, "B"*16).decrypt("C"*16) == (
        "\x0b\xd4\x18\xa6\xf7\xbd\x1a\xff\x16\x1f\xd1A\xd4\xbe5\x9b"
    )

def test_short_aes():
    # Note that ECB doesn't use the IV.
    assert aes.ecb.decrypt("A"*16, "B"*16, "C"*32) == (
        "I\x96Z\xe4\xb5\xffX\xbdT]\x93\x03\x96\xfcw\xd9"
        "I\x96Z\xe4\xb5\xffX\xbdT]\x93\x03\x96\xfcw\xd9"
    )
    assert aes.ecb.decrypt("A"*16, data="C"*32) == (
        "I\x96Z\xe4\xb5\xffX\xbdT]\x93\x03\x96\xfcw\xd9"
        "I\x96Z\xe4\xb5\xffX\xbdT]\x93\x03\x96\xfcw\xd9"
    )

    assert aes.cbc.decrypt("A"*16, "B"*16, "C"*32) == (
        "\x0b\xd4\x18\xa6\xf7\xbd\x1a\xff\x16\x1f\xd1A\xd4\xbe5\x9b"
        "\n\xd5\x19\xa7\xf6\xbc\x1b\xfe\x17\x1e\xd0@\xd5\xbf4\x9a"
    )

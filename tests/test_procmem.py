# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import os
import struct
import tempfile

from roach import procmem, pad, insn, PAGE_READWRITE

def test_procmem_dummy_dmp():
    p = procmem("tests/files/dummy.dmp")
    assert len(p.regions) == 3
    assert p.regions[0].to_json() == {
        "addr": "0x41410000",
        "end": "0x41411000",
        "offset": 24,
        "size": 0x1000,
        "state": 0,
        "type": 0,
        "protect": "rwx",
    }
    assert p.regions[1].to_json() == {
        "addr": "0x41411000",
        "end": "0x41413000",
        "offset": 4144,
        "protect": "r",
        "size": 0x2000,
        "state": 42,
        "type": 43,
    }
    assert p.regions[2].to_json() == {
        "addr": "0x42420000",
        "end": "0x42421000",
        "offset": 12360,
        "protect": "r",
        "size": 0x1000,
        "state": 0,
        "type": 0,
    }

    p = procmem("tests/files/dummy.dmp", False)
    assert len(p.regions) == 3
    assert p.readv(0x41410f00, 0x200) == "A"*0xf4 + "X"*4 + "A"*8 + "B"*0x100
    assert p.uint8p(p.v2p(0x41410fff)) == 0x41
    assert p.uint8v(0x41410fff) == 0x41
    assert p.uint16p(p.v2p(0x4141100f)) == 0x4242
    assert p.uint16v(0x4141100f) == 0x4242
    assert p.uint32p(p.v2p(0x42420000)) == 0x43434343
    assert p.uint32v(0x42420000) == 0x43434343
    assert p.uint64p(p.v2p(0x41410ff8)) == 0x4141414141414141
    assert p.uint64v(0x41410ffe) == 0x4242424242424141
    assert p.p2v(p.v2p(0x41411414)) == 0x41411414

def test_methods():
    fd, filepath = tempfile.mkstemp()
    os.write(fd, "".join((
        struct.pack("QIIII", 0x401000, 0x1000, 0, 0, PAGE_READWRITE),
        pad.null("foo\x00bar thisis0test hAAAA\xc3", 0x1000),
    )))
    os.close(fd)
    buf = procmem(filepath)
    assert buf.readv(0x401000, 0x1000).endswith("\x00"*0x100)
    assert buf.regexv("thisis(.*)test") == 0x401008
    assert buf.disasmv(0x401014, 6) == [
        insn("push", 0x41414141, addr=0x401014),
        insn("ret", addr=0x401019),
    ]

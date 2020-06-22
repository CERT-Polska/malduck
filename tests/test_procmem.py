# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import os
import struct
import tempfile
import pytest

from malduck import procmem, procmempe, cuckoomem, pad, pe, insn, PAGE_READWRITE, enhex
from malduck.procmem import Region


def test_readv():
    payload = b"".join([
        b"a" * 0x1000,
        b"b" * 0x1000,
        b"c" * 0x1000,
        b"d" * 0x1000
    ])
    regions = [
        Region(0x400000, 0x1000, 0, 0, 0, 0),
        Region(0x401000, 0x1000, 0, 0, 0, 0x1000),
        Region(0x402000, 0x1000, 0, 0, 0, 0x2000),
        Region(0x410000, 0x1000, 0, 0, 0, 0x3000),
    ]

    p = procmem(payload, regions=regions)
    assert p.readv(0x3fffff, 16) == b""
    assert p.readv(0x400000, 16) == b"a" * 16
    assert isinstance(p.readv(0x400000, 16), bytes)
    assert p.readv(0x400fff, 16) == b"a" + b"b" * 15
    assert p.readv(0x400ffe, 0x1100) == b"aa" + (b"b" * 0x1000) + (b"c" * 0xfe)
    assert p.readv(0x402ffe, 0x1000) == b"cc"
    assert p.readv(0x402ffe) == b"cc"
    assert p.readv(0x403000) == b""
    assert p.readv(0x401000) == b"b" * 0x1000 + b"c" * 0x1000
    assert p.readv(0x40ffff) == b""
    assert p.readv(0x410000) == b"d" * 0x1000
    assert p.readv(0x410ffe) == b"dd"


def test_cuckoomem_dummy_dmp():
    with cuckoomem.from_file("tests/files/dummy.dmp") as p:
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

        assert len(p.regions) == 3
        assert p.readv(0x41410f00, 0x200) == b"A"*0xf4 + b"X"*4 + b"A"*8 + b"B"*0x100
        assert isinstance(p.readv(0x41410f00, 0x200), bytes)
        assert p.uint8p(p.v2p(0x41410fff)) == 0x41
        assert p.uint8v(0x41410fff) == 0x41
        assert p.uint16p(p.v2p(0x4141100f)) == 0x4242
        assert p.uint16v(0x4141100f) == 0x4242
        assert p.uint32p(p.v2p(0x42420000)) == 0x43434343
        assert p.uint32v(0x42420000) == 0x43434343
        assert p.uint64p(p.v2p(0x41410ff8)) == 0x4141414141414141
        assert p.uint64v(0x41410ffe) == 0x4242424242424141
        assert p.p2v(p.v2p(0x41411414)) == 0x41411414

        assert p.uint8v(0x1000) is None
        assert p.uint16v(0x1000) is None
        assert p.uint32v(0x1000) is None
        assert p.uint64v(0x1000) is None


def test_calc_dmp():
    with cuckoomem.from_file("tests/files/calc.dmp") as p:
        ppe = procmempe.from_memory(p, 0xd0000)
        assert p.regions == ppe.regions
        assert p.findmz(0x129abc) == 0xd0000
        # Old/regular method with PE header.
        assert pe(p.readv(p.imgbase, 0x1000)).dos_header.e_lfanew == 0xd8
        assert p.readv(p.imgbase + 0xd8, 4) == b"PE\x00\x00"

        assert pe(p).is32bit is True
        d = pe(p).optional_header.DATA_DIRECTORY[2]
        assert d.VirtualAddress == 0x59000 and d.Size == 0x62798
        data = pe(p).resource(b"WEVT_TEMPLATE")
        assert data.startswith(b"CRIM")
        assert len(data) == 4750
        assert len(ppe.pe.section(".text").get_data()) == 0x52e00


def test_calc_exe():
    with procmempe.from_file("tests/files/calc.exe", image=True) as ppe:
        assert ppe.imgbase == 0x1000000
        assert ppe.readv(ppe.imgbase + 0xd8, 4) == b"PE\x00\x00"
        assert ppe.pe.is32bit is True
        d = ppe.pe.optional_header.DATA_DIRECTORY[2]
        assert d.VirtualAddress == 0x59000 and d.Size == 0x62798
        data = ppe.pe.resource("WEVT_TEMPLATE")
        assert data.startswith(b"CRIM")
        assert len(data) == 4750
        # Check relocations
        assert not ppe.readv(0x10016C2, 4) == 0x10551f8
        assert len(ppe.pe.section(".text").get_data()) == 0x52e00


def test_cuckoomem_methods():
    fd, filepath = tempfile.mkstemp()
    os.write(fd, b"".join((
        struct.pack("QIIII", 0x401000, 0x1000, 0, 0, PAGE_READWRITE),
        pad.null(b"foo\x00bar thisis0test\n hAAAA\xc3", 0x1000),
    )))
    os.close(fd)
    with cuckoomem.from_file(filepath) as buf:
        assert buf.readv(0x401000, 0x1000).endswith(b"\x00"*0x100)
        assert list(buf.regexv(b"thisis(.*)test", 0x401000)) == [0x401008]
        assert list(buf.regexv(b" ", 0x401000)) == [0x401007, 0x401014]
        assert list(buf.regexv(b" ", 0x401000, 0x10)) == [0x401007]
        assert list(buf.regexv(b"test..h", 0x401000)) == [0x40100f]
        assert buf.disasmv(0x401015, 6) == [
            insn("push", 0x41414141, addr=0x401015),
            insn("ret", addr=0x40101a),
        ]


def test_utf16z():
    payload = b"\x00\x00a\x00b\x00c\x00\x00\x00"
    p = procmem(payload, base=0x400000)
    assert p.utf16z(0x400000) == b""
    assert p.utf16z(0x400002) == b"abc"


def test_findbytes():
    payload = b" " * 0x1000 + pad.null(
        b"\xffoo\x00bar thisis0test\n hAAAA\xc3\xc0\xc2\xc4\n\n\x10\x2f\x1f\x1a\x1b\x1f\x1d\xbb\xcc\xdd\xff",
        0x10000)
    buf = procmem(payload, base=0x400000)
    assert list(buf.findbytesv("c? c? c? 0A")) == [0x40101B]
    assert list(buf.findbytesv(b"1f ?? ?b")) == [0x401022, 0x401025]
    assert list(buf.findbytesv("?f ?? ?? 00")) == [0x401000, 0x40102A]
    assert not list(buf.findbytesv(enhex(b"test hAAAA")))
    assert list(buf.findbytesv(enhex(b"test\n hAAAA")))

    assert list(buf.findbytesv(enhex(b"is"), length=0x100b)) == [0x40100a]
    assert list(buf.findbytesv(enhex(b"is"), length=0x100d)) == [0x40100a, 0x40100c]
    assert list(buf.findbytesv(enhex(b"is"), addr=0x40100b, length=0x100d)) == [0x40100c]

    payload = b"".join([
        b"a" * 0x1000,
        b"b" * 0x1000,
        b"c" * 0x1000,
        b"d" * 0x1000
    ])
    regions = [
        Region(0x400000, 0x1000, 0, 0, 0, 0),
        Region(0x401000, 0x1000, 0, 0, 0, 0x1000),
        Region(0x402000, 0x1000, 0, 0, 0, 0x2000),
        Region(0x410000, 0x1000, 0, 0, 0, 0x3000),
    ]

    p = procmem(payload, regions=regions)
    assert next(p.findbytesv(enhex(b"dddd"))) == 0x410000


def test_simple_findv():
    payload = b"12ab34cd45ef"
    regions = [
        Region(0x10000, 2, 0, 0, 0, 2),
        Region(0x10002, 2, 0, 0, 0, 6),
        Region(0x10010, 2, 0, 0, 0, 10)
    ]
    p = procmem(payload, regions=regions)

    assert list(p.findv(b"12")) == []
    assert list(p.findv(b"ab")) == [0x10000]
    assert list(p.findv(b"ab", addr=0x10002)) == []
    assert list(p.findv(b"ab34")) == []
    assert list(p.findv(b"abcd")) == [0x10000]
    assert list(p.findv(b"abcdef")) == []
    assert list(p.findv(b"cdef")) == []
    assert list(p.findv(b"ef")) == [0x10010]


def test_findv():
    payload = b"".join([
        pad.null(pad.null(b"a" * 0x200 + b"pattern", 0x500) + b"pattern2", 0x1000),
        pad.null(pad.null(b"b" * 0x200 + b"pattern", 0x500) + b"pattern2", 0x1000),
        b"c" * 0x1000,
        pad.null(pad.null(b"d" * 0x200 + b"pattern", 0x500) + b"pattern2", 0x1000)
    ])
    regions = [
        Region(0x400000, 0x1000, 0, 0, 0, 0),
        Region(0x401000, 0x1000, 0, 0, 0, 0x1000),
        Region(0x402000, 0x1000, 0, 0, 0, 0x2000),
        Region(0x410000, 0x1000, 0, 0, 0, 0x3000),
    ]
    p = procmem(payload, regions=regions)

    assert list(p.findv(b"pattern")) == [0x400200, 0x400500, 0x401200, 0x401500, 0x410200, 0x410500]
    assert list(p.findv(b"pattern", 0x401100, 0x405)) == [0x401200]
    assert list(p.findv(b"pattern", length=0x10300)) == [0x400200, 0x400500, 0x401200, 0x401500, 0x410200]
    assert list(p.findv(b"pattern", 0x401508)) == [0x410200, 0x410500]
    assert list(p.findv(b"pattern", 0x403508)) == [0x410200, 0x410500]


def test_patchv():
    payload = b"".join([
        b"a" * 0x1000,
        b"b" * 0x1000,
        b"c" * 0x1000,
        b"d" * 0x1000
    ])
    regions = [
        Region(0x400000, 0x1000, 0, 0, 0, 0),
        Region(0x401000, 0x1000, 0, 0, 0, 0x1000),
        Region(0x402000, 0x1000, 0, 0, 0, 0x2000),
        Region(0x410000, 0x1000, 0, 0, 0, 0x3000),
    ]

    p = procmem(payload, regions=regions)
    with pytest.raises(ValueError, match="Address is out of single region"):
        p.patchv(0x3fffff, b"p" * 16)
    p.patchv(0x400000, b"p" * 16)
    assert p.readv(0x400000, 17) == b"p" * 16 + b"a"
    with pytest.raises(ValueError, match="Address is out of single region"):
        p.patchv(0x401fff, b"p" * 2)


def test_procmempe_image_sections():
    with procmempe.from_file("tests/files/96emptysections.exe", image=True) as p:
        assert p.store() == p.readp(0)
        original_data = p.pe.sections[0].get_data()
        stored_pe = p.store()
    p = procmempe(stored_pe, image=True)
    stored_data = p.pe.sections[0].get_data()
    assert original_data == stored_data
    assert len(p.pe.sections) == 96

    with procmempe.from_file("tests/files/96workingsections.exe", image=True) as p:
        assert p.store() == p.readp(0)
        stored_pe = p.store()
    p = procmempe(stored_pe, image=True)
    assert len(p.pe.sections) == 96

    with procmempe.from_file("tests/files/96emptysections.exe.bin") as p:
        assert p.readv(0x2000, 8) == b"\x68\x28\x20\x40\x00\xe8\x0e\x00"

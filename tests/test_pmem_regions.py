import pytest

from malduck import procmem
from malduck.procmem import Region


def test_single_region():
    payload = b"0123456789"
    regions = [
        Region(0x10000, 8, 0, 0, 0, 1)
    ]
    mem = procmem(payload, regions=regions)
    assert list(mem.iter_regions()) == mem.regions

    assert list(mem.iter_regions(addr=0xffff)) == mem.regions
    assert list(mem.iter_regions(addr=0x10000)) == mem.regions
    assert list(mem.iter_regions(addr=0x10007)) == mem.regions
    assert list(mem.iter_regions(addr=0x10008)) == []

    assert list(mem.iter_regions(offset=0)) == mem.regions
    assert list(mem.iter_regions(offset=1)) == mem.regions
    assert list(mem.iter_regions(offset=8)) == mem.regions
    assert list(mem.iter_regions(offset=9)) == []

    assert list(mem.iter_regions(length=0)) == []
    assert list(mem.iter_regions(length=1)) == mem.regions

    assert list(mem.iter_regions(addr=0xffff, length=1)) == []
    assert list(mem.iter_regions(addr=0xffff, length=2)) == mem.regions
    assert list(mem.iter_regions(addr=0xffff, length=0x10)) == mem.regions
    assert list(mem.iter_regions(addr=0x10007, length=0x10)) == mem.regions
    assert list(mem.iter_regions(addr=0x10008, length=0x10)) == []

    with pytest.raises(ValueError):
        # ValueError("Don't know how to retrieve length-limited regions with offset from unmapped area")
        list(mem.iter_regions(offset=0, length=1))
    assert list(mem.iter_regions(offset=1, length=1)) == mem.regions


def test_single_region_trim():
    payload = b"0123456789"
    regions = [
        Region(0x10000, 8, 0, 0, 0, 1)
    ]
    mem = procmem(payload, regions=regions)
    assert list(mem.iter_regions(trim=True)) == mem.regions

    assert list(mem.iter_regions(addr=0xffff, trim=True)) == mem.regions
    assert list(mem.iter_regions(addr=0x10000, trim=True)) == mem.regions
    assert list(mem.iter_regions(addr=0x10007, trim=True)) == [Region(0x10007, 1, 0, 0, 0, 8)]
    assert list(mem.iter_regions(addr=0x10008, trim=True)) == []

    assert list(mem.iter_regions(offset=0, trim=True)) == mem.regions
    assert list(mem.iter_regions(offset=1, trim=True)) == mem.regions
    assert list(mem.iter_regions(offset=8, trim=True)) == [Region(0x10007, 1, 0, 0, 0, 8)]
    assert list(mem.iter_regions(offset=9, trim=True)) == []

    assert list(mem.iter_regions(length=0, trim=True)) == []
    assert list(mem.iter_regions(length=1, trim=True)) == [Region(0x10000, 1, 0, 0, 0, 1)]

    assert list(mem.iter_regions(addr=0xffff, length=1, trim=True)) == []
    assert list(mem.iter_regions(addr=0xffff, length=2, trim=True)) == [Region(0x10000, 1, 0, 0, 0, 1)]
    assert list(mem.iter_regions(addr=0xffff, length=8, trim=True)) == [Region(0x10000, 7, 0, 0, 0, 1)]
    assert list(mem.iter_regions(addr=0x10001, length=4, trim=True)) == [Region(0x10001, 4, 0, 0, 0, 2)]
    assert list(mem.iter_regions(addr=0x10007, length=0x10, trim=True)) == [Region(0x10007, 1, 0, 0, 0, 8)]
    assert list(mem.iter_regions(addr=0x10008, length=0x10, trim=True)) == []

    with pytest.raises(ValueError):
        # ValueError("Don't know how to retrieve length-limited regions with offset from unmapped area")
        list(mem.iter_regions(offset=0, length=1, trim=True))
    assert list(mem.iter_regions(offset=1, length=1, trim=True)) == [Region(0x10000, 1, 0, 0, 0, 1)]
    assert list(mem.iter_regions(offset=4, length=2, trim=True)) == [Region(0x10003, 2, 0, 0, 0, 4)]


@pytest.fixture
def mem():
    #            aaaaaaa  bbbbbbccccccccdddd   eeee
    payload = b"0123456789abcdefghijklmnopqrstuvwxyz"
    regions = [
        Region(0x10000, 7, 0, 0, 0, 1),
        Region(0x10007, 6, 0, 0, 0, 10),
        Region(0x10100, 8, 0, 0, 0, 16),
        Region(0x10108, 4, 0, 0, 0, 24),
        Region(0x10200, 4, 0, 0, 0, 31)
    ]
    #          v---0x10000            v---- 0x10100          v-- 0x10200
    # VM: .....1234567abcdef..........ghijklmnopqr ..........vwxy.......
    return procmem(payload, base=0x10000, regions=regions)


def test_regions_multi(mem):
    # Test simple enum from specified address
    assert list(mem.iter_regions()) == mem.regions
    assert list(mem.iter_regions(0x1000)) == mem.regions
    assert list(mem.iter_regions(0x10000)) == mem.regions
    assert list(mem.iter_regions(0x10104)) == [Region(0x10100, 8, 0, 0, 0, 16),
                                               Region(0x10108, 4, 0, 0, 0, 24),
                                               Region(0x10200, 4, 0, 0, 0, 31)]
    assert list(mem.iter_regions(0x10203)) == [Region(0x10200, 4, 0, 0, 0, 31)]
    assert list(mem.iter_regions(0x10204)) == []

    # Test simple enum from specified offset
    assert list(mem.iter_regions(offset=0)) == mem.regions
    assert list(mem.iter_regions(offset=10)) == mem.regions[1:]
    assert list(mem.iter_regions(offset=20)) == mem.regions[2:]
    assert list(mem.iter_regions(offset=30)) == [Region(0x10200, 4, 0, 0, 0, 31)]
    assert list(mem.iter_regions(offset=40)) == []

    assert list(mem.iter_regions(0xffff, contiguous=True)) == []
    assert list(mem.iter_regions(0x10000, contiguous=True)) == [Region(0x10000, 7, 0, 0, 0, 1),
                                                                Region(0x10007, 6, 0, 0, 0, 10)]
    assert list(mem.iter_regions(0x10002, length=8, contiguous=True, trim=True)) == [
        Region(0x10002, 5, 0, 0, 0, 3),
        Region(0x10007, 3, 0, 0, 0, 10)
    ]
    assert list(mem.iter_regions(offset=1, contiguous=True)) == [
        Region(0x10000, 7, 0, 0, 0, 1),
        Region(0x10007, 6, 0, 0, 0, 10)
    ]
    assert list(mem.iter_regions(offset=2, length=0x9f)) == [
        Region(0x10000, 7, 0, 0, 0, 1),
        Region(0x10007, 6, 0, 0, 0, 10)
    ]
    assert list(mem.iter_regions(offset=2, length=0x100)) == [
        Region(0x10000, 7, 0, 0, 0, 1),
        Region(0x10007, 6, 0, 0, 0, 10),
        Region(0x10100, 8, 0, 0, 0, 16)
    ]
    assert list(mem.iter_regions(offset=2, length=0x100, trim=True)) == [
        Region(0x10001, 6, 0, 0, 0, 2),
        Region(0x10007, 6, 0, 0, 0, 10),
        Region(0x10100, 1, 0, 0, 0, 16)
    ]


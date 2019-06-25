# Copyright (C) 2018 Jurriaan Bremer.
# Copyright (C) 2018 Hatching B.V.
# This file is part of Roach - https://github.com/jbremer/malduck.
# See the file 'docs/LICENSE.txt' for copying permission.

import io

from malduck import pe, base64, procmempe, cuckoomem


def test_pe_header():
    img = pe(base64("""
TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1v
ZGUuDQ0KJAAAAAAAAACCixJ5xup8KsbqfCrG6nwqz5LpKsfqfCrhLBEqxOp8KuEsByrU6nwqxup9
KnjqfCoF5SEqxep8KgXlIyrH6nwqBeVzKsXqfCrPkvUq2ep8Kti46CrH6nwqz5LtKsfqfCpSaWNo
xup8KgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFBFAABMAQUAE5z9WAAAAAAAAAAA4AADAQsBCQAA
bgAAACoAAAAAAADnEAAAABAAAACAAAAAAEAAABAAAAACAAAFAAAAAAAAAAUAAAAAAAAAAJAEAAAE
AAAAAAAAAgAAgAAAEAAAEAAAAAAQAAAQAAAAAAAAEAAAAAAAAAAAAAAARIQAAMgAAAAAwAAAEAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAACAAACYAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALnRleHQAAADQ
bAAAABAAAABuAAAABAAAAAAAAAAAAAAAAAAAIAAAYC5yZGF0YQAA/hIAAACAAAAAFAAAAHIAAAAA
AAAAAAAAAAAAAEAAAEAuZGF0YQAAAGQKAAAAoAAAAAgAAACGAAAAAAAAAAAAAAAAAABAAADALmJz
cwAAAAARBwAAALAAAAAIAAAAjgAAAAAAAAAAAAAAAAAAQAAAwC5yc3JjAAAAANADAADAAAAAzAMA
AJYAAAAAAAAAAAAAAAAAAEAAAEAK
""".strip()))
    assert img.dos_header.e_magic == 0x5a4d
    assert img.nt_headers.Signature == 0x4550
    assert img.file_header.NumberOfSections == len(img.sections)
    assert img.sections[0].Name.strip("\x00") == ".text"
    assert img.sections[-1].get_file_offset() == 0x298
    assert img.is32bit is True
    assert img.is64bit is False
    assert img.section(".text").VirtualAddress == 0x1000


def test_calc_exe():
    p = pe(open("tests/files/calc.exe", "rb").read(), fast_load=False)
    assert p.is32bit is True
    data = p.resource("WEVT_TEMPLATE")
    assert data.startswith("CRIM")
    assert len(data) == 4750

    icons = list(p.resources("RT_ICON"))
    assert len(icons) == 16
    assert len(icons[0]) == 2664
    assert len(icons[7]) == 2216
    assert len(icons[11]) == 16936

    bitmaps = list(p.resources(51209))
    assert len(bitmaps) == 1
    assert len(bitmaps[0]) == 22042


def test_ollydbg_exe():
    p = pe(open("tests/files/ollydbg.exe", "rb").read(), fast_load=False)
    assert p.is32bit is True
    data = p.resource("DVCLAL")
    assert data.startswith("\xA2\x8C\xDF\x98")
    assert len(data) == 16


def test_pe2procmem():
    # @todo
    return
    """
    a = pe(open("tests/files/calc.exe", "rb").read())
    b = cuckoomem(open("tests/files/calc.exe", "rb").read())
    assert a.sections[2].SizeOfRawData == b.regions[3].size
    assert a.sections[3].get_data() == b.readv(
        b.regions[4].addr, b.regions[4].size
    )
    """

import os

from malduck import procmem, procmempe
from malduck.extractor import ExtractorModules, ExtractManager


def test_scan_base64():
    modules = ExtractorModules("tests/files/modules")
    assert "Unbase64" in [extractor.__name__ for extractor in modules.extractors]

    for fname in os.listdir("tests/files"):
        fpath = os.path.join("tests/files", fname)
        if os.path.isfile(fpath):
            extractor = ExtractManager(modules)
            extractor.push_file(fpath)
            if extractor.config:
                assert len(extractor.config) == 1
                matched_base = extractor.config[0].get("base64", False)
            else:
                matched_base = False
            should_be_base = fname.endswith(".b64")
            # To be or not to be
            assert matched_base == should_be_base


def test_scan_ollydbg():
    modules = ExtractorModules("tests/files/modules")
    olly = procmempe.from_file("tests/files/ollydbg.exe", image=True)
    cfg = olly.extract(modules)[0]

    assert cfg["family"] == "ollydbg"
    assert sorted(cfg["olly"]) == [
        b' - OllyDbg is a JIT debugger\n',
        b" - OllyDbg is in Explorer's menu\n",
        b" - OllyDbg is not in Explorer's menu"
    ]


def test_apliebe():
    modules = ExtractorModules("tests/files/modules")
    p = procmem.from_file("tests/files/mal1.b64")
    assert p.extract(modules) == [{
        "base64": True,
        "family": "apliebe",
        "str_to_int_offs": [0x1000a410]
    }]


def test_weaky():
    modules = ExtractorModules("tests/files/modules")
    weaky = procmem(b"weakyx")
    strongy = procmem(b"strongy")
    strongyweaky = procmem(b"strongyweakyx")
    assert not weaky.extract(modules)
    assert strongy.extract(modules) == [{
        "family": "weaky"
    }]
    assert strongyweaky.extract(modules) == [{
        "family": "weaky",
        "weak": True,
        "weaky": True
    }]

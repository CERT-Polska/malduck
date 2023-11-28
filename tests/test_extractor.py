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
        " - OllyDbg is a JIT debugger\n",
        " - OllyDbg is in Explorer's menu\n",
        " - OllyDbg is not in Explorer's menu"
    ]
    assert "olly_is_not" in cfg["matches"]


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


def test_multirules():
    modules = ExtractorModules("tests/files/modules")
    multistring = procmem(b"FiRsT string fIrSt string"
                          b"SeCoNd string sEcOnD string"
                          b"ThIrD string tHiRd string")
    assert multistring.extract(modules) == [{
        'family': 'multistring',
        'first': ['FiRsT string', 'fIrSt string', 'SeCoNd string', 'sEcOnD string'],
        'third': ['ThIrD string']
    }]

    multistring_v2 = procmem(b"ThIrD stringa0a1b2b3c4c5d6d7e8e9FoUrTh string")
    assert multistring_v2.extract(modules) == [{
        'family': 'multistring_v2',
        'matched': ['v2'],
        'third': ['ThIrD string']
    }]


def test_configmerge():
    modules = ExtractorModules("tests/files/modules")
    calc_exe_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "files", "calc.exe")
    extractor = ExtractManager(modules)
    extractor.push_file(calc_exe_path)
    assert len(extractor.config) == 1

    conf = extractor.config[0]
    assert conf == {
        'family': "ConfigMerge",
        'constant': "CONST",
        'mem_types': [str(procmem), str(procmempe)],
        'dict': {
            '0x0': "imagebase",
            '0x1000000': "imagebase"
        }
    }

    
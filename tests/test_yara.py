import os

from malduck import Yara, YaraString, YaraStringMatch
from malduck.procmem import Region, ProcessMemory


def test_yara_match():
    yara = Yara(strings={
        "program1": YaraString("Program", wide=True, nocase=True),
        "program2": YaraString("Program", ascii=True),
        "program3": "margorP",
        "program4": YaraString("90 90 90 ff", type=YaraString.HEX)
    })

    match = yara.match(data="This program cannot be run in DOS mode".encode("utf16"))

    assert match
    assert "r" in match
    assert match.r
    assert match["r"]
    assert "r" in match.keys()

    assert sorted(match.r.keys()) == ["program", "program1"]
    assert match.r.get_offsets("program") == [12]
    assert match.r.get_offsets("program1") == [12]

    match = yara.match(data=b"margorP\x90\x90\x90\xffProgram")
    assert match
    assert sorted(match.r.keys()) == ["program", "program2", "program3", "program4"]
    assert sorted(match.r.get_offsets("program")) == [
        match.r.program3[0].hit,
        match.r.program4[0].hit,
        match.r.program2[0].hit]


def test_yara_escaping():
    assert str(YaraString("\"alamakota\"akot\nma'ale'")) == "\"\\\"alamakota\\\"akot\\nma'ale'\""
    assert str(YaraString("23 3? [5-6] 20", type=YaraString.HEX)) == '{ 23 3? [5-6] 20 }'
    assert str(YaraString(r"/home/(ripper|extractor)", type=YaraString.REGEX)) == r'/\/home\/(ripper|extractor)/'
    Yara(strings={
        "alamakota": YaraString("\"alamakota\"akot\nma'ale'"),
        "hexy": YaraString("23 3? [5-6] 20", type=YaraString.HEX),
        "pathy": YaraString(r"/home/(ripper|extractor)", type=YaraString.REGEX)
    })


def test_yara_dirs_and_files():
    local_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "files", "yara")
    all_rules = Yara.from_dir(local_path)
    inner_rules = Yara.from_dir(local_path, recursive=False)

    match = all_rules.match(filepath=os.path.join(local_path, "calc.exe"))
    # FourSectionPE doesn't have any strings
    assert sorted(match.keys()) == ["Calc"]
    assert match.Calc.calc == [
        YaraStringMatch(identifier='calc', hit=0xb996c, content=b'C\x00A\x00L\x00C\x00.\x00E\x00X\x00E\x00')
    ]

    match = all_rules.match(filepath=os.path.join(local_path, "dummy.dmp"))
    assert sorted(match.keys()) == ["DummyRoachRule"]
    assert sorted(match.DummyRoachRule.keys()) == ["region_bc", "region_bc1", "region_bc2"]
    # Strings must be ordered by hits
    assert match.DummyRoachRule.region_bc == [
        YaraStringMatch(identifier='region_bc2',
                        hit=0x1014,
                        content=b'AAAA\x00\x10AA\x00\x00\x00\x00\x00 \x00\x00*\x00\x00\x00'
                                b'+\x00\x00\x00\x02\x00\x00\x00BBBB'),
        YaraStringMatch(identifier='region_bc1',
                        hit=0x302c,
                        content=b'BBBB\x00\x00BB\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00'
                                b'\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00CCCC'),
    ]

    match = inner_rules.match(filepath=os.path.join(local_path, "calc.exe"))
    assert match

    match = inner_rules.match(filepath=os.path.join(local_path, "dummy.dmp"))
    assert not match


def test_procmem_yara():
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

    p = ProcessMemory(payload, regions=regions)
    ruleset = Yara(
        name="regions",
        strings={
            "a_series": "a" * 64,
            "b_series": "b" * 64,
            "c_series": "c" * 64,
            "d_series": "d" * 64,
            "a_and_b":  "a" * 64 + "b" * 64,
            "b_and_c":  "b" * 64 + "c" * 64,
            "c_and_d":  "c" * 64 + "d" * 64
        },
        condition="$a_series and $b_series and $c_series and $d_series and $a_and_b and ( $b_and_c or $c_and_d )"
    )
    matchp = p.yarap(ruleset)
    matchv = p.yarav(ruleset)

    assert matchp
    assert matchv
    assert set(matchp.regions.keys()).difference(set(matchv.regions.keys())) == {"c_and_d"}

    assert [matchv.regions.a_and_b[0].hit, matchv.regions.b_and_c[0].hit] == [0x400fc0, 0x401fc0]
    assert matchv.regions.get_offsets("a_series") == list(range(0x400000, 0x401000 - 63))
    assert matchv.regions.get_offsets("b_series") == list(range(0x401000, 0x402000 - 63))
    assert matchv.regions.get_offsets("c_series") == list(range(0x402000, 0x403000 - 63))
    assert matchv.regions.get_offsets("d_series") == list(range(0x410000, 0x411000 - 63))
    assert matchv.regions.get("a_series")
    assert not matchv.regions.get("e_series")


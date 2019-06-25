# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/malduck.
# See the file 'docs/LICENSE.txt' for copying permission.

from malduck import aes, blowfish, des3, rc4, rsa, xor, base64, unhex, rabbit

def test_aes():
    assert aes.ecb.decrypt("A"*16, "C"*32) == (
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

    assert aes.ctr(
        "hello world12345", "A"*16,
        "\x803\xe3J#\xf4;\x13\x11+h\xf5\xba-\x9b\x05"
    ) == "B"*16

    assert aes.import_key(
        "\x08\x02\x00\x00\x0ef\x00\x00\x10\x00\x00\x00" + "A"*16
    ) == ("AES-128", "A"*16)

def test_blowfish():
    assert blowfish(
        "blowfish", "\x91;\x92\xa9\x85\x83\xb36\xbb\xac\xa8r0\xf1$\x19"
    ) == "_hello world01!?"

def test_des():
    assert des3.cbc.decrypt(
        "A"*8, "B"*8, "\x1d\xed\xc37pV\x89S\xac\xaeT\xaf\xa1\xcfW\xa3"
    ) == "C"*16

def test_rc4():
    assert rc4.encrypt("Key", "Plaintext") == unhex("bbf316e8d940af0ad3")
    assert rc4.decrypt("Wiki", "pedia") == unhex("1021bf0420")
    assert rc4.decrypt("Secret", "Attack at dawn") == (
        unhex("45a01f645fc35b383552544b9bf5")
    )
    assert rc4("hello", "world") == unhex("783ecd96cf")

def test_xor():
    assert xor(
        0xff, "\x97\x9a\x93\x93\x90\xdf\x88\x90\x8d\x93\x9b"
    ) == "hello world"
    assert xor(
        "hi!", "\x00\x0cM\x04\x06\x01\x1f\x06S\x04\r"
    ) == "hello world"

def test_rsa():
    assert rsa.import_key(base64("""
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5cagCPVB7LiX3UI5N3WRQJqTLe5RPrhFj79/U
7AY+ziYQrKhSaIQG7KWuLAZj4sKRyRyZK1te0Ekb1UGkYn3b1YTQtXojaakq5p4WyHFvhfNPjSlJ
ClIt4QC/NZ9uS2FRee8ONEKODrcgevzcd+lbNy/mGAB7yW9XgP06YzfOyQIDAQAB
    """)) == """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5cagCPVB7LiX3UI5N3WRQJqTL
e5RPrhFj79/U7AY+ziYQrKhSaIQG7KWuLAZj4sKRyRyZK1te0Ekb1UGkYn3b1YTQ
tXojaakq5p4WyHFvhfNPjSlJClIt4QC/NZ9uS2FRee8ONEKODrcgevzcd+lbNy/m
GAB7yW9XgP06YzfOyQIDAQAB
-----END PUBLIC KEY-----
""".strip()

    assert rsa.import_key(base64("""
BwIAAACkAABSU0EyAAQAAAEAAQCxTx++ykWtb2UaYFYQLt1yM893SV/wLehU2DwzeAMpxq5MsOF5
XVAd1qSElMN8Uqxdn7FXuT4XFJjH2o6MsnkheoWKPmIC357IUk/N/49dyjtk14In+HdxWKKoguXd
lOfGoriyieo8cr4kYCoYGPpHNv50NlZi3jkzQvW+hVK6v/ufshtYBRd/+NjecYVQlt7ivap8d/9g
szM+eSC91zZm8OPUCmfQX8AJOq9r7LUB/tS5DLswtJZdDDmpjhbGf/ZDg+YhHFPYvRlnGP4PlXBW
Qds44ZlSJJ780+tDuxP3Zn1Nfch4IZjkATGx7Zd9tzr8iLDe0zAGzJDaV92qHR7Hn5V5VGH1dZk2
DMiR1893vJfuE9RwDja6hUycXNjj9Y1fCYGK3rsVGO7+Dg9xab3HFqueydlMgir8MD4jShsaXk2P
jUYp2KdJuyN6BZP1oorUntgJIJGeoK59w5Vxni64rJp6KKhsKiOWM37cWAVYmd3dc0PeF3R9s/1Y
nTMtXoo1r77CjBv5q+zvMSzeFUl+ji9beSZbzl9rAvJOBw4v1Bj8EzPq5aYvEs7h9M66BbZjuyeH
zp2sRBuxE6K13j1AIVHCK7gbVwlieHWKuE5d45ealzSsChwoxGlJcHlHBI62zQqo7SHbb2An72IS
XtyKY18/3bYV4nv6ydeC9zgpVlNfGwgwP05Rkp7ldJsCz7uT6RAANV86JIp+65SCKs4gcgWWPIbn
KJ4s7fs/3oy7tUSTdviZShGj2cJGiEIyIiA=
    """)) == """
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC/ulKFvvVCMzneYlY2dP42R/oYGCpgJL5yPOqJsriixueU3eWC
qKJYcXf4J4LXZDvKXY//zU9SyJ7fAmI+ioV6IXmyjI7ax5gUFz65V7GfXaxSfMOU
hKTWHVBdeeGwTK7GKQN4MzzYVOgt8F9Jd88zct0uEFZgGmVvrUXKvh9PsQIDAQAB
AoGAICIyQohGwtmjEUqZ+HaTRLW7jN4/++0snijnhjyWBXIgziqClOt+iiQ6XzUA
EOmTu88Cm3TlnpJRTj8wCBtfU1YpOPeC18n6e+IVtt0/X2OK3F4SYu8nYG/bIe2o
Cs22jgRHeXBJacQoHAqsNJeal+NdTriKdXhiCVcbuCvCUSECQQD2f8YWjqk5DF2W
tDC7DLnU/gG17GuvOgnAX9BnCtTj8GY2170geT4zs2D/d3yqveLellCFcd7Y+H8X
BVgbsp/7AkEAxx4dqt1X2pDMBjDT3rCI/Dq3fZftsTEB5JgheMh9TX1m9xO7Q+vT
/J4kUpnhONtBVnCVD/4YZxm92FMcIeaDQwJAXhobSiM+MPwqgkzZyZ6rFse9aXEP
Dv7uGBW73oqBCV+N9ePYXJxMhbo2DnDUE+6XvHfP15HIDDaZdfVhVHmVnwJBAIpe
LTOdWP2zfXQX3kNz3d2ZWAVY3H4zliMqbKgoepqsuC6ecZXDfa6gnpEgCdie1Iqi
9ZMFeiO7SafYKUaNj00CQEA93rWiE7EbRKydzocnu2O2BbrO9OHOEi+m5eozE/wY
1C8OB07yAmtfzlsmeVsvjn5JFd4sMe/sq/kbjMK+rzU=
-----END RSA PRIVATE KEY-----
""".strip()

    assert rsa.import_key(base64("""
BgIAAACkAABSU0ExAAQAAAEAAQChEcfAbVoL/jUnFMxI+xsR0zZUvMZ+9pgkLGpaxTiLRP6PZqx8
lDdwqdb7gC+m5aOz+Uwms6RHrY/xRMYEXopj877qLancMtsiqcpASOYJWxWSgW+gQMJGldwn2H97
AaHoqFlbn7NW6oNtpz4C7NotiggtVnqLdE8YyNfO6/gEpQ==
""")) == """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQClBPjrztfIGE90i3pWLQiKLdrs
Aj6nbYPqVrOfW1mo6KEBe3/YJ9yVRsJAoG+BkhVbCeZIQMqpItsy3Kkt6r7zY4pe
BMZE8Y+tR6SzJkz5s6Plpi+A+9apcDeUfKxmj/5EizjFWmosJJj2fsa8VDbTERv7
SMwUJzX+C1ptwMcRoQIDAQAB
-----END PUBLIC KEY-----
""".strip()

    assert rsa.import_key("") is None

    # This obviously doesn't make any sense, but it's to ensure that the
    # None or long wrapping is working, avoiding PyCrypto complains.
    assert rsa.export_key(0x10001, 0x10001) == """
-----BEGIN PUBLIC KEY-----
MB4wDQYJKoZIhvcNAQEBBQADDQAwCgIDAQABAgMBAAE=
-----END PUBLIC KEY-----
""".strip()

def test_rabbit():
    key1 = "".join(chr(ch) for ch in (
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ))

    key2 = "".join(chr(ch) for ch in (
        0xAC, 0xC3, 0x51, 0xDC, 0xF1, 0x62, 0xFC, 0x3B,
        0xFE, 0x36, 0x3D, 0x2E, 0x29, 0x13, 0x28, 0x91,
    ))

    key3 = "".join(chr(ch) for ch in (
        0x43, 0x00, 0x9B, 0xC0, 0x01, 0xAB, 0xE9, 0xE9,
        0x33, 0xC7, 0xE0, 0x87, 0x15, 0x74, 0x95, 0x83,
    ))

    iv1 = "".join(chr(ch) for ch in (
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ))

    iv2 = "".join(chr(ch) for ch in (
        0x59, 0x7E, 0x26, 0xC1, 0x75, 0xF5, 0x73, 0xC3,
    ))

    iv3 = "".join(chr(ch) for ch in (
        0x27, 0x17, 0xF4, 0xD2, 0x1A, 0x56, 0xEB, 0xA6,
    ))

    out1 = "".join(chr(ch) for ch in (
        0x02, 0xF7, 0x4A, 0x1C, 0x26, 0x45, 0x6B, 0xF5,
        0xEC, 0xD6, 0xA5, 0x36, 0xF0, 0x54, 0x57, 0xB1,
        0xA7, 0x8A, 0xC6, 0x89, 0x47, 0x6C, 0x69, 0x7B,
        0x39, 0x0C, 0x9C, 0xC5, 0x15, 0xD8, 0xE8, 0x88,
        0x96, 0xD6, 0x73, 0x16, 0x88, 0xD1, 0x68, 0xDA,
        0x51, 0xD4, 0x0C, 0x70, 0xC3, 0xA1, 0x16, 0xF4,
    ))

    out2 = "".join(chr(ch) for ch in (
        0x9C, 0x51, 0xE2, 0x87, 0x84, 0xC3, 0x7F, 0xE9,
        0xA1, 0x27, 0xF6, 0x3E, 0xC8, 0xF3, 0x2D, 0x3D,
        0x19, 0xFC, 0x54, 0x85, 0xAA, 0x53, 0xBF, 0x96,
        0x88, 0x5B, 0x40, 0xF4, 0x61, 0xCD, 0x76, 0xF5,
        0x5E, 0x4C, 0x4D, 0x20, 0x20, 0x3B, 0xE5, 0x8A,
        0x50, 0x43, 0xDB, 0xFB, 0x73, 0x74, 0x54, 0xE5,
    ))

    out3 = "".join(chr(ch) for ch in (
        0x9B, 0x60, 0xD0, 0x02, 0xFD, 0x5C, 0xEB, 0x32,
        0xAC, 0xCD, 0x41, 0xA0, 0xCD, 0x0D, 0xB1, 0x0C,
        0xAD, 0x3E, 0xFF, 0x4C, 0x11, 0x92, 0x70, 0x7B,
        0x5A, 0x01, 0x17, 0x0F, 0xCA, 0x9F, 0xFC, 0x95,
        0x28, 0x74, 0x94, 0x3A, 0xAD, 0x47, 0x41, 0x92,
        0x3F, 0x7F, 0xFC, 0x8B, 0xDE, 0xE5, 0x49, 0x96,
    ))

    out4 = "".join(chr(ch) for ch in (
        0xED, 0xB7, 0x05, 0x67, 0x37, 0x5D, 0xCD, 0x7C,
        0xD8, 0x95, 0x54, 0xF8, 0x5E, 0x27, 0xA7, 0xC6,
        0x8D, 0x4A, 0xDC, 0x70, 0x32, 0x29, 0x8F, 0x7B,
        0xD4, 0xEF, 0xF5, 0x04, 0xAC, 0xA6, 0x29, 0x5F,
        0x66, 0x8F, 0xBF, 0x47, 0x8A, 0xDB, 0x2B, 0xE5,
        0x1E, 0x6C, 0xDE, 0x29, 0x2B, 0x82, 0xDE, 0x2A,
    ))

    out5 = "".join(chr(ch) for ch in (
        0x6D, 0x7D, 0x01, 0x22, 0x92, 0xCC, 0xDC, 0xE0,
        0xE2, 0x12, 0x00, 0x58, 0xB9, 0x4E, 0xCD, 0x1F,
        0x2E, 0x6F, 0x93, 0xED, 0xFF, 0x99, 0x24, 0x7B,
        0x01, 0x25, 0x21, 0xD1, 0x10, 0x4E, 0x5F, 0xA7,
        0xA7, 0x9B, 0x02, 0x12, 0xD0, 0xBD, 0x56, 0x23,
        0x39, 0x38, 0xE7, 0x93, 0xC3, 0x12, 0xC1, 0xEB,
    ))

    out6 = "".join(chr(ch) for ch in (
        0x4D, 0x10, 0x51, 0xA1, 0x23, 0xAF, 0xB6, 0x70,
        0xBF, 0x8D, 0x85, 0x05, 0xC8, 0xD8, 0x5A, 0x44,
        0x03, 0x5B, 0xC3, 0xAC, 0xC6, 0x67, 0xAE, 0xAE,
        0x5B, 0x2C, 0xF4, 0x47, 0x79, 0xF2, 0xC8, 0x96,
        0xCB, 0x51, 0x15, 0xF0, 0x34, 0xF0, 0x3D, 0x31,
        0x17, 0x1C, 0xA7, 0x5F, 0x89, 0xFC, 0xCB, 0x9F,
    ))

    assert rabbit(key1, None, "\x00"*48) == out1
    assert rabbit(key2, None, "\x00"*48) == out2
    assert rabbit(key3, None, "\x00"*48) == out3

    assert rabbit(key1, iv1, "\x00"*48) == out4
    assert rabbit(key1, iv2, "\x00"*48) == out5
    assert rabbit(key1, iv3, "\x00"*48) == out6

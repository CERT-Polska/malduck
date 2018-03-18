# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach import md5, sha1, sha224, sha256, sha384, sha512

def test_hash():
    assert md5("hello").encode("hex") == "5d41402abc4b2a76b9719d911017c592"
    assert sha1("hello").encode("hex") == (
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    )
    assert sha224("hello").encode("hex") == (
        "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193"
    )
    assert sha256("hello").encode("hex") == (
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )
    assert sha384("hello").encode("hex") == (
        "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f"
    )
    assert sha512("hello").encode("hex") == (
        "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
    )

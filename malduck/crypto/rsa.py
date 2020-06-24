# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import io

from Cryptodome.PublicKey import RSA as RSA_
from itertools import takewhile

from .winhdr import BLOBHEADER, BaseBlob
from ..string.bin import uint32, bigint
from io import BytesIO
from typing import Optional, cast

__all__ = ["PublicKeyBlob", "PrivateKeyBlob", "RSA", "rsa"]


class PublicKeyBlob(BaseBlob):
    magic = b"RSA1"

    def __init__(self) -> None:
        BaseBlob.__init__(self)
        self.e: Optional[int] = None
        self.n: Optional[int] = None

    def parse(self, buf: BytesIO) -> Optional[int]:
        header = buf.read(12)
        if len(header) != 12 or header[:4] != self.magic:
            return None

        self.bitsize = cast(int, uint32(header[4:8], fixed=False))
        self.e = cast(int, uint32(header[8:12], fixed=False))

        n = buf.read(self.bitsize // 8)
        if len(n) != self.bitsize // 8:
            return None

        self.n = bigint.unpack(n)
        return 12 + self.bitsize // 8

    def export_key(self) -> bytes:
        if not (self.e and self.n):
            raise ValueError("The imported key is invalid")
        return RSA.export_key(self.n, self.e)


class PrivateKeyBlob(PublicKeyBlob):
    magic = b"RSA2"

    def __init__(self) -> None:
        PublicKeyBlob.__init__(self)
        self.p1: Optional[int] = None
        self.p2: Optional[int] = None
        self.exp1: Optional[int] = None
        self.exp2: Optional[int] = None
        self.coeff: Optional[int] = None
        self.d: Optional[int] = None

    def parse(self, buf: BytesIO) -> None:
        off = PublicKeyBlob.parse(self, buf)
        if not off:
            return

        self.p1 = bigint.unpack(buf.read(self.bitsize // 16))
        if self.p1 is None:
            return

        self.p2 = bigint.unpack(buf.read(self.bitsize // 16))
        if self.p2 is None:
            return

        self.exp1 = bigint.unpack(buf.read(self.bitsize // 16))
        if self.exp1 is None:
            return

        self.exp2 = bigint.unpack(buf.read(self.bitsize // 16))
        if self.exp2 is None:
            return

        self.coeff = bigint.unpack(buf.read(self.bitsize // 16))
        if self.coeff is None:
            return

        self.d = bigint.unpack(buf.read(self.bitsize // 8))
        if self.d is None:
            return

    def export_key(self) -> bytes:
        if not (self.e and self.n):
            raise ValueError("The imported key is invalid")
        return RSA.export_key(self.n, self.e, self.d)


BlobTypes = {
    6: PublicKeyBlob,
    7: PrivateKeyBlob,
}


class RSA:
    algorithms = (0x0000A400,)  # RSA

    @staticmethod
    def import_key(data: bytes) -> Optional[bytes]:
        r"""
        Extracts key from buffer containing :class:`PublicKeyBlob` or :class:`PrivateKeyBlob` data

        :param data: Buffer with `BLOB` structure data
        :type data: bytes
        :return: RSA key in PEM format
        :rtype: bytes
        """
        try:
            return RSA_.import_key(data).export_key()
        except (ValueError, IndexError):
            pass

        if len(data) < BLOBHEADER.sizeof():
            return None

        buf = io.BytesIO(data)
        header = BLOBHEADER.parse(buf.read(BLOBHEADER.sizeof()))
        if header.bType not in BlobTypes:
            return None

        if header.aiKeyAlg not in RSA.algorithms:
            return None

        obj = BlobTypes[header.bType]()
        obj.parse(buf)
        return obj.export_key()

    @staticmethod
    def export_key(
        n: int,
        e: int,
        d: Optional[int] = None,
        p: Optional[int] = None,
        q: Optional[int] = None,
        crt: Optional[int] = None,
    ) -> bytes:
        r"""
        Constructs key from tuple of RSA components

        :param n: RSA modulus n
        :param e: Public exponent e
        :param d: Private exponent d
        :param p: First factor of n
        :param q: Second factor of n
        :param crt: CRT coefficient q
        :return: RSA key in PEM format
        :rtype: bytes
        """

        def wrap(x):
            return None if x is None else int(x)

        tup = wrap(n), wrap(e), wrap(d), wrap(p), wrap(q), wrap(crt)
        # PyCryptodome accepts only variable-length tuples
        tup_w = tuple(takewhile(lambda x: x is not None, tup))
        return RSA_.construct(tup_w, consistency_check=False).export_key()  # type: ignore


rsa = RSA

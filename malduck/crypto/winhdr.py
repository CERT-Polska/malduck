# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import io
from typing import Any, Optional

from ..ints import UInt8, UInt16, UInt32
from ..structure import Structure


class BLOBHEADER(Structure):
    r"""
    Windows BLOBHEADER structure

    .. seealso::

        BLOBHEADER structure description (Microsoft Docs):
        https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-publickeystruc
    """
    _pack_ = 1
    _fields_ = [
        ("bType", UInt8),
        ("bVersion", UInt8),
        ("wReserved", UInt16),
        ("aiKeyAlg", UInt32),
    ]


class BaseBlob:
    def __init__(self) -> None:
        self.bitsize = 0

    def parse(self, buf: io.BytesIO) -> Optional[int]:
        raise NotImplementedError

    def export_key(self) -> Any:
        raise NotImplementedError

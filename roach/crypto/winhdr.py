# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach.string.bin import uint8, uint16, uint32
from roach.structure import Structure

class BLOBHEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ("bType", uint8),
        ("bVersion", uint8),
        ("wReserved", uint16),
        ("aiKeyAlg", uint32),
    ]

class BaseBlob(object):
    def __init__(self):
        self.bitsize = 0

    def parse(self, buf):
        raise NotImplementedError

    def export_key(self):
        raise NotImplementedError

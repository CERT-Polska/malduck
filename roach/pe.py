# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import pefile

class PE(object):
    def __init__(self, data):
        self.data = data
        self.pe = pefile.PE(data=data, fast_load=True)

    @property
    def dos_header(self):
        return self.pe.DOS_HEADER

    @property
    def nt_headers(self):
        return self.pe.NT_HEADERS

    @property
    def optional_header(self):
        return self.pe.OPTIONAL_HEADER

    @property
    def sections(self):
        return self.pe.sections

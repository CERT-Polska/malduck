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
    def file_header(self):
        return self.pe.FILE_HEADER

    @property
    def optional_header(self):
        return self.pe.OPTIONAL_HEADER

    @property
    def sections(self):
        return self.pe.sections

    @property
    def is32bit(self):
        return self.optional_header.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE

    @property
    def is64bit(self):
        return (
            self.optional_header.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
        )

    def section(self, name):
        for section in self.pe.sections:
            if section.Name.rstrip("\x00") == name:
                return section

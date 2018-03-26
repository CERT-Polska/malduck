# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import pefile

from roach.procmem import ProcessMemoryPE, ProcessMemory

class OurSectionStructure(pefile.SectionStructure):
    def get_data(self, start=None, length=None):
        if not isinstance(self.pe.__data__, ProcessMemoryPE):
            return OrigSectionStructure.get_data(self, start, length)
        data = self.pe.__data__
        return data.readv(data.imgbase + start, length)

OrigSectionStructure = pefile.SectionStructure
pefile.SectionStructure = OurSectionStructure

class PE(object):
    """Wrapper around pefile.PE; accepts either a string (raw file contents) or
    a ProcessMemoryPE instance."""

    def __init__(self, data, fast_load=True):
        if data.__class__ == ProcessMemory:
            raise RuntimeError("procmem parameter should be procmempe!")

        if data.__class__ == ProcessMemoryPE:
            fast_load = False
            data.parent = self

        self.data = data
        self.pe = pefile.PE(data=data, fast_load=fast_load)

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

    def resources(self, name):
        name_str = lambda e1, e2, e3: e1.name and e1.name.string == name
        name_int = lambda e1, e2, e3: e2.struct.Name == name
        type_int = lambda e1, e2, e3: e1.id == type_id

        if isinstance(name, basestring):
            if name.startswith("RT_"):
                compare = type_int
                type_id = pefile.RESOURCE_TYPE[name]
            else:
                compare = name_str
        else:
            compare = name_int

        for e1 in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for e2 in e1.directory.entries:
                for e3 in e2.directory.entries:
                    if compare(e1, e2, e3):
                        yield self.pe.get_data(
                            e3.data.struct.OffsetToData, e3.data.struct.Size
                        )

    def resource(self, name):
        try:
            return next(self.resources(name))
        except StopIteration:
            pass

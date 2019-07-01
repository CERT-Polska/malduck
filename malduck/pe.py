# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import pefile
from .py2compat import binary_type, text_type, ensure_bytes, ensure_string


class MemoryPEData(object):
    """
    `pefile.PE.__data__` represents image file usually aligned to 512 bytes.
    MemoryPEData perform mapping from pefile's offset-access to Memory object va-access
    based on section layout.
    """

    def __init__(self, memory, fast_load):
        self.memory = memory
        # Preload headers
        self.pe = pefile.PE(data=self, fast_load=True)
        # Perform full_load if needed
        if not fast_load:
            self.pe.full_load()

    def map_offset(self, offs):
        if not hasattr(self, "pe") or not self.pe.sections:
            return self.memory.imgbase + offs
        return self.memory.imgbase + (self.pe.get_rva_from_offset(offs) or offs)

    def __len__(self):
        r = self.memory.regions[-1]
        return r.addr + r.size

    def __getitem__(self, item):
        if type(item) is slice:
            start = self.map_offset(item.start or 0)
            stop = self.map_offset(item.stop)
        else:
            start = self.map_offset(item)
            stop = start + 1
        return self.memory.readv(start, stop - start)

    def find(self, str, beg=0, end=None):
        return next(self.memory.regexv(str, self.memory.imgbase + beg, end-beg))


class PE(object):
    """
    Wrapper around :class:`pefile.PE`, accepts either bytes (raw file contents) or :class:`ProcessMemory` instance.
    """

    def __init__(self, data, fast_load=False):
        from .procmem import ProcessMemory
        if isinstance(data, ProcessMemory):
            self.data = MemoryPEData(data, fast_load)
            self.pe = self.data.pe
        else:
            self.data = data
            self.pe = pefile.PE(data=data, fast_load=fast_load)

    @property
    def dos_header(self):
        """Dos header"""
        return self.pe.DOS_HEADER

    @property
    def nt_headers(self):
        """NT headers"""
        return self.pe.NT_HEADERS

    @property
    def file_header(self):
        """File header"""
        return self.pe.FILE_HEADER

    @property
    def optional_header(self):
        """Optional header"""
        return self.pe.OPTIONAL_HEADER

    @property
    def sections(self):
        """Sections"""
        return self.pe.sections

    @property
    def is32bit(self):
        """
        Is it 32-bit file (PE)?
        """
        return self.optional_header.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE

    @property
    def is64bit(self):
        """
        Is it 64-bit file (PE+)?
        """
        return (
            self.optional_header.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
        )

    def section(self, name):
        """
        Get section by name

        :param name: Section name
        :type name: str or bytes
        """
        for section in self.pe.sections:
            if section.Name.rstrip(b"\x00") == ensure_bytes(name):
                return section

    def resources(self, name):
        """
        Finds resource objects by specified name or type

        :param name: String name (e2) or type (e1), numeric identifier name (e2) or RT_* type (e1)
        :type name: int or str or bytes
        :rtype: Iterator[bytes]
        """
        name_str = lambda e1, e2, e3: (e1.name and e1.name.string == name) or (e2.name and e2.name.string == name)
        name_int = lambda e1, e2, e3: e2.struct.Name == name
        type_int = lambda e1, e2, e3: e1.id == type_id

        if isinstance(name, text_type):
            name = ensure_bytes(name)

        if isinstance(name, binary_type):
            if name.startswith(b"RT_"):
                compare = type_int
                type_id = pefile.RESOURCE_TYPE[ensure_string(name)]
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
        """
        Retrieves single resource by specified name or type

        :param name: String name (e2) or type (e1), numeric identifier name (e2) or RT_* type (e1)
        :type name: int or str or bytes
        :rtype: bytes or None
        """
        try:
            return next(self.resources(name))
        except StopIteration:
            pass


def pe2cuckoo(data):
    from .procmem import ProcessMemoryPE, CuckooProcessMemory
    """Translate a PE file into a cuckoo-procmem file."""
    m = ProcessMemoryPE(data, image=True)
    return CuckooProcessMemory.from_memory(m).store()

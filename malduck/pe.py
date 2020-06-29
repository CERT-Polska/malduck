# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import pefile

from typing import Any, Iterator, Optional, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from .procmem import ProcessMemory

__all__ = ["pe", "PE", "MemoryPEData", "FastPE"]


class FastPE(pefile.PE):
    def set_bytes_at_offset(self, offset, data):
        """
        Overwrite the bytes at the given file offset with the given string.

        Return True if successful, False otherwise. It can fail if the
        offset is outside the file's boundaries.

        Remove after merge of https://github.com/erocarrera/pefile/pull/266
        """

        if not isinstance(data, bytes):
            raise TypeError("data should be of type: bytes")

        if 0 <= offset < len(self.__data__):
            if isinstance(self.__data__, bytearray):
                self.__data__[offset : offset + len(data)] = data
            else:
                self.__data__ = (
                    self.__data__[:offset] + data + self.__data__[offset + len(data) :]
                )
        else:
            return False

        return True


class MemoryPEData:
    """
    `pefile.PE.__data__` represents image file usually aligned to 512 bytes.
    MemoryPEData perform mapping from pefile's offset-access to Memory object va-access
    based on section layout.
    """

    def __init__(self, memory: "ProcessMemory", fast_load: bool) -> None:
        self.memory = memory
        # Preload headers
        self.pe = FastPE(data=self, fast_load=True)
        # Perform full_load if needed
        if not fast_load:
            self.pe.full_load()

    def map_offset(self, offs: int) -> int:
        if not hasattr(self, "pe") or not self.pe.sections:
            return self.memory.imgbase + offs
        return self.memory.imgbase + (self.pe.get_rva_from_offset(offs) or offs)

    def __len__(self) -> int:
        return (
            self.memory.regions[-1].addr
            - self.memory.regions[0].addr
            + self.memory.regions[-1].size
        )

    def __getitem__(self, item: Any) -> object:
        if isinstance(item, slice):
            start = self.map_offset(item.start or 0)
            stop = self.map_offset(item.stop - 1)
        else:
            start = self.map_offset(item)
            stop = start
        return self.memory.readv(start, stop - start + 1)

    def find(self, str: bytes, beg: int = 0, end: Optional[int] = None) -> int:
        if end and beg >= end:
            return -1
        try:
            return next(
                self.memory.regexv(str, self.memory.imgbase + beg, end and end - beg)
            )
        except StopIteration:
            return -1


class PE(object):
    """
    Wrapper around :class:`pefile.PE`, accepts either bytes (raw file contents) or
    :class:`ProcessMemory` instance.
    """

    def __init__(
        self, data: Union["ProcessMemory", bytes], fast_load: bool = False
    ) -> None:
        from .procmem import ProcessMemory

        if isinstance(data, ProcessMemory):
            self.pe = MemoryPEData(data, fast_load).pe
        else:
            self.pe = FastPE(data=data, fast_load=fast_load)

    @property
    def data(self) -> bytes:
        return self.pe.__data__

    @property
    def dos_header(self) -> Any:
        """Dos header"""
        return self.pe.DOS_HEADER

    @property
    def nt_headers(self) -> Any:
        """NT headers"""
        return self.pe.NT_HEADERS

    @property
    def file_header(self) -> Any:
        """File header"""
        return self.pe.FILE_HEADER

    @property
    def optional_header(self) -> Any:
        """Optional header"""
        return self.pe.OPTIONAL_HEADER

    @property
    def sections(self) -> list:
        """Sections"""
        return self.pe.sections

    @property
    def is32bit(self) -> Any:
        """
        Is it 32-bit file (PE)?
        """
        return self.optional_header.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE

    @property
    def is64bit(self) -> Any:
        """
        Is it 64-bit file (PE+)?
        """
        return self.optional_header.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS

    @property
    def headers_size(self) -> int:
        """
        Estimated size of PE headers (first section offset).
        If there are no sections: returns 0x1000 or size of input if provided data are shorter than single page
        """
        return (
            self.sections[0].PointerToRawData
            if self.sections
            else min(len(self.pe.__data__), 0x1000)
        )

    def section(self, name: Union[str, bytes]) -> Any:
        """
        Get section by name

        :param name: Section name
        :type name: str or bytes
        """
        if isinstance(name, str):
            name = name.encode()

        for section in self.pe.sections:
            if section.Name.rstrip(b"\x00") == name:
                return section

    def directory(self, name: str) -> Any:
        """
        Get pefile directory entry by identifier

        :param name: shortened pefile directory entry identifier (e.g. 'IMPORT' for 'IMAGE_DIRECTORY_ENTRY_IMPORT')
        :rtype: :class:`pefile.Structure`
        """
        return self.optional_header.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY.get("IMAGE_DIRECTORY_ENTRY_" + name)
        ]

    def structure(self, rva: int, format: Any) -> Any:
        """
        Get internal pefile Structure from specified rva

        :param rva: Relative virtual address of structure
        :param format: :class:`pefile.Structure` format
                       (e.g. :py:attr:`pefile.PE.__IMAGE_LOAD_CONFIG_DIRECTORY64_format__`)
        :rtype: :class:`pefile.Structure`
        """
        structure = pefile.Structure(format)
        structure.__unpack__(self.pe.get_data(rva, structure.sizeof()))
        return structure

    def validate_import_names(self) -> bool:
        """
        Returns True if the first 8 imported library entries have valid library names
        """
        import_dir = self.directory("IMPORT")
        if not import_dir.VirtualAddress:
            # There's nothing wrong with no imports
            return True
        try:
            import_rva = import_dir.VirtualAddress
            # Don't go further than 8 entries
            for _ in range(8):
                import_desc = self.structure(
                    import_rva, pefile.PE.__IMAGE_IMPORT_DESCRIPTOR_format__
                )
                if import_desc.all_zeroes():
                    # End of import-table
                    break
                import_dllname = self.pe.get_string_at_rva(
                    import_desc.Name, pefile.MAX_DLL_LENGTH
                )
                if not pefile.is_valid_dos_filename(import_dllname):
                    # Invalid import filename found
                    return False
                import_rva += import_desc.sizeof()
            return True
        except pefile.PEFormatError:
            return False

    def validate_resources(self) -> bool:
        """
        Returns True if first level of resource tree looks consistent
        """
        resource_dir = self.directory("RESOURCE")
        if not resource_dir.VirtualAddress:
            # There's nothing wrong with no resources
            return True
        try:
            resource_rva = resource_dir.VirtualAddress
            resource_desc = self.structure(
                resource_rva, pefile.PE.__IMAGE_RESOURCE_DIRECTORY_format__
            )
            resource_no = (
                resource_desc.NumberOfNamedEntries + resource_desc.NumberOfIdEntries
            )
            if not 0 <= resource_no < 128:
                # Incorrect resource number
                return False
            for rsrc_idx in range(resource_no):
                resource_entry_desc = self.structure(
                    resource_rva + resource_desc.sizeof() + rsrc_idx * 8,
                    pefile.PE.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__,
                )
                if (
                    self.pe.get_word_at_rva(
                        resource_rva + resource_entry_desc.OffsetToData & 0x7FFFFFFF
                    )
                    is None
                ):
                    return False
            return True
        except pefile.PEFormatError:
            return False

    def validate_padding(self) -> bool:
        """
        Returns True if area between first non-bss section and first 4kB doesn't have only null-bytes
        """
        section_start_offs = None
        for section in self.sections:
            if section.SizeOfRawData > 0:
                section_start_offs = section.PointerToRawData
                break
        if section_start_offs is None:
            # No non-bss sections? Is it real PE file?
            return False
        if section_start_offs > 0x1000:
            # Unusual - try checking last 512 bytes
            section_start_offs = 0x800
        try:
            data_len = 0x1000 - section_start_offs
            if not data_len:
                # Probably fixpe'd - seems to be ok
                return True
            return not all(
                b in [0, "\0"]
                for b in self.pe.__data__[
                    section_start_offs : section_start_offs + data_len
                ]
            )
        except pefile.PEFormatError:
            return False

    def resources(self, name: Union[int, str, bytes]) -> Iterator[bytes]:
        """
        Finds resource objects by specified name or type

        :param name: String name (e2) or type (e1), numeric identifier name (e2) or RT_* type (e1)
        :type name: int or str or bytes
        :rtype: Iterator[bytes]
        """

        def name_str(e1, e2, e3):
            return (e1.name and e1.name.string == name) or (
                e2.name and e2.name.string == name
            )

        def name_int(e1, e2, e3):
            return e2.struct.Name == name

        def type_int(e1, e2, e3):
            return e1.id == type_id

        if isinstance(name, str):
            name = name.encode()

        if isinstance(name, bytes):
            if name.startswith(b"RT_"):
                compare = type_int
                type_id = pefile.RESOURCE_TYPE[name.decode()]
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

    def resource(self, name: Union[int, str, bytes]) -> Optional[bytes]:
        """
        Retrieves single resource by specified name or type

        :param name: String name (e2) or type (e1), numeric identifier name (e2) or RT_* type (e1)
        :type name: int or str or bytes
        :rtype: bytes or None
        """
        try:
            return next(self.resources(name))
        except StopIteration:
            return None


pe = PE

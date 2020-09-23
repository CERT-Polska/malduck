from typing import List, Optional

from .binmem import ProcessMemoryBinary
from .procmem import ProcessMemoryBuffer
from .region import Region

from ..bits import align
from ..pe import PE

__all__ = ["ProcessMemoryPE", "procmempe"]


class ProcessMemoryPE(ProcessMemoryBinary):
    """
    Representation of memory-mapped PE file

    Short name: `procmempe`

    :param buf: A memory object containing the PE to be loaded
    :type buf: bytes, mmap, memoryview, bytearray or :py:meth:`MemoryBuffer` object

    :param base: Virtual address of the region of interest (or beginning of buf when no regions provided)
    :type base: int, optional (default: 0)

    :param image: The memory object is a dump of memory-mapped PE
    :type image: bool, optional (default: False)

    :param detect_image: Try to automatically detect if the input buffer is memory-mapped PE using some heuristics
    :type detect_image: bool, optional (default: False)

    File `memory_dump` contains a 64bit memory-aligned PE dumped from address `0x140000000`, in order to load it
    into procmempe and access the `pe` field all we have to do is initialize a new object with the file data:

    .. code-block:: python

        from malduck import procmempe

        with open("memory_dump", "rb") as f:
            data = f.read()

        pe_dump = procmempe(buf=data, base=0x140000000, image=True)
        print(pe_dump.pe.is64bit)


    PE files can also be read directly using inherited :py:meth:`ProcessMemory.from_file` with `image` argument set
    (look at :py:meth:`from_memory` method).

    .. code-block:: python

        pe_dump = procmempe.from_file("140000000_1d5bdc3dbe71a7bd", image=True)
        print(pe_dump.pe.sections)
    """

    __magic__ = b"MZ"

    def __init__(
        self,
        buf: ProcessMemoryBuffer,
        base: int = 0,
        regions: Optional[List[Region]] = None,
        image: bool = False,
        detect_image: bool = False,
    ) -> None:
        self._pe: Optional[PE] = None
        super(ProcessMemoryPE, self).__init__(
            buf, base=base, regions=regions, image=image, detect_image=detect_image
        )

    def _pe_direct_load(self, fast_load: bool = True) -> PE:
        offset = self.v2p(self.imgbase)
        if offset is None:
            raise ValueError("imgbase out of regions")
        # Expected m type: bytearray
        m = bytearray(self.readp(offset))
        pe = PE(data=m, fast_load=fast_load)
        return pe

    def _reload_as_image(self) -> None:
        # Load PE data from imgbase offset
        pe = self._pe_direct_load(fast_load=False)
        # If mmap: close all descriptors or
        # nullify references if mmap is not owned by current object
        self.close()
        # Set memory to the pe.data buffer
        self.memory = bytearray(pe.data)
        self.imgbase = pe.optional_header.ImageBase
        # Reset regions
        self.regions = [Region(self.imgbase, pe.headers_size, 0, 0, 0, 0)]
        # Load image sections
        for section in pe.sections:
            if section.SizeOfRawData > 0:
                self.regions.append(
                    Region(
                        self.imgbase + section.VirtualAddress,
                        section.SizeOfRawData,
                        0,
                        0,
                        0,
                        section.PointerToRawData,
                    )
                )

    def is_valid(self) -> bool:
        if self.readv(self.imgbase, 2) != self.__magic__:
            return False
        pe_offs = self.uint32v(self.imgbase + 0x3C)
        if pe_offs is None:
            return False
        if self.readv(self.imgbase + pe_offs, 2) != b"PE":
            return False
        try:
            PE(self)
            return True
        except Exception:
            return False

    def is_image_loaded_as_memdump(self) -> bool:
        """
        Checks whether memory region contains image incorrectly loaded as memory-mapped PE dump (image=False).

        .. code-block:: python

           embed_pe = procmempe.from_memory(mem)
           if not embed_pe.is_image_loaded_as_memdump():
               # Memory contains plain PE file - need to load it first
               embed_pe = procmempe.from_memory(mem, image=True)
        """
        pe = self._pe_direct_load(fast_load=True)
        # If import table is corrupted - possible dump
        if not pe.validate_import_names():
            return False
        # If resources are corrupted - possible dump
        if not pe.validate_resources():
            return False
        # If first 4kB seem to be zero-padded - possible dump
        if not pe.validate_padding():
            return False
        # No errors, so it must be PE file
        return True

    @property
    def pe(self) -> PE:
        """Related :class:`PE` object"""
        if self._pe is None:
            self._pe = PE(self)
        return self._pe

    @property
    def imgend(self) -> int:
        """Address where PE image ends"""
        section = self.pe.sections[-1]
        return self.imgbase + section.VirtualAddress + section.Misc_VirtualSize

    def store(self) -> bytes:
        """
        Store ProcessMemoryPE contents as PE file data.

        :rtype: bytes
        """
        data = []
        current_offs = self.pe.headers_size
        # Read headers (until first section page in raw data)
        pe = PE(self.readv(self.imgbase, current_offs), fast_load=True)

        for idx, section in enumerate(pe.sections):
            # Find corresponding region
            section_region = self.addr_region(self.imgbase + section.VirtualAddress)
            # No corresponding region? BSS.
            if not section_region:
                continue
            # Get possible section size
            section_size = max(section.Misc_VirtualSize, section.SizeOfRawData)
            # Align to section alignment (usually 0x1000)
            section_alignment = max(0x1000, pe.optional_header.SectionAlignment)
            section_size = align(section_size, section_alignment)
            # Sometimes real region size is less than virtual size (image=True)
            section_size = min(section_region.size, section_size)
            # Align to file alignment (usually 0x200)
            file_alignment = max(0x200, pe.optional_header.FileAlignment)
            section_size = align(section_size, file_alignment)
            # Read section data including appropriate padding
            section_data = self.readv(
                self.imgbase + section.VirtualAddress, section_size
            )
            section_data += (section_size - len(section_data)) * b"\x00"
            data.append(section_data)
            # Fix section values
            section.PointerToRawData, section.SizeOfRawData = current_offs, section_size
            current_offs += section_size

        pe.optional_header.ImageBase = self.imgbase

        # Generate header data
        pe_data = b"".join([bytes(pe.pe.write())] + data)

        # Return PE file data
        return pe_data


procmempe = ProcessMemoryPE

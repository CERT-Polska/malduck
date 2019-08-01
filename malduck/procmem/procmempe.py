from .region import Region
from .procmem import ProcessMemory

from ..bits import align
from ..pe import PE


class ProcessMemoryPE(ProcessMemory):
    """
    Representation of memory-mapped PE file

    Short name: `procmempe`

    PE files can be read directly using inherited :py:meth:`ProcessMemory.from_file` with `image` argument set
    (look at :py:meth:`from_memory` method).
    """
    def __init__(self, buf, base=0, regions=None, image=False, detect_image=False):
        super(ProcessMemoryPE, self).__init__(buf, base=base, regions=regions)
        self._pe = None
        self._imgend = None
        if detect_image:
            image = self.is_image_loaded_as_memdump()
        if image:
            self._load_image()

    @classmethod
    def from_memory(cls, memory, base=None, image=False, detect_image=False):
        """
        Creates ProcessMemoryPE instance from ProcessMemory object.

        :param memory: ProcessMemory object containing PE image
        :type memory: :class:`ProcessMemory`
        :param base: Virtual address where PE image is located (default: beginning of procmem)
        :param image: True if memory contains EXE file instead of memory-mapped PE (default: False)
        :param detect_image: ProcessMemoryPE automatically detect whether image or memory-mapped PE is loaded
                             (default: False)
        :rtype: :class:`ProcessMemoryPE`

        When image is True - PE file will be loaded under location specified in PE header
        (pe.optional_header.ImageBase). :class:`ProcessMemoryPE` object created that way contains only memory regions
        created during load (all other data will be wiped out). If image contains relocation info, relocations will be
        applied using :py:meth:`pefile.relocate_image` method.
        """
        copied = cls(memory.m, base=base or memory.imgbase, regions=memory.regions,
                     image=image, detect_image=detect_image)
        copied.f = memory.f
        return copied

    def _pe_direct_load(self, fast_load=True):
        offset = self.v2p(self.imgbase)
        # Expected m type: bytearray
        m = bytearray(self.readp(offset))
        pe = PE(data=m, fast_load=fast_load)
        return pe

    def _load_image(self):
        # Load PE data from imgbase offset
        pe = self._pe_direct_load(fast_load=False)
        # Reset regions
        self.m = pe.data
        self.imgbase = pe.optional_header.ImageBase

        self.regions = [
            Region(self.imgbase, pe.headers_size, 0, 0, 0, 0)
        ]
        # Load image sections
        for section in pe.sections:
            if section.SizeOfRawData > 0:
                self.regions.append(Region(
                    self.imgbase + section.VirtualAddress,
                    section.SizeOfRawData,
                    0, 0, 0,
                    section.PointerToRawData
                ))

    def is_image_loaded_as_memdump(self):
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
    def pe(self):
        """Related :class:`PE` object"""
        if not self._pe:
            self._pe = PE(self)
        return self._pe

    @property
    def imgend(self):
        """Address where PE image ends"""
        if not self._imgend:
            section = self.pe.sections[-1]
            self._imgend = (
                self.imgbase +
                section.VirtualAddress + section.Misc_VirtualSize
            )
        return self._imgend

    def store(self):
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
            section_data = self.readv(self.imgbase + section.VirtualAddress, section_size)
            section_data += (section_size - len(section_data)) * b'\x00'
            data.append(section_data)
            # Fix section values
            section.PointerToRawData, section.SizeOfRawData = current_offs, section_size
            current_offs += section_size

        pe.optional_header.ImageBase = self.imgbase

        # Generate header data
        data = b''.join([bytes(pe.pe.write())] + data)

        # Return PE file data
        return data

from .region import Region
from .procmem import ProcessMemory
from ..pe import PE


class ProcessMemoryPE(ProcessMemory):
    """
    Representation of memory-mapped PE file

    Short name: `procmempe`

    PE files can be read directly using inherited :py:meth:`ProcessMemory.from_file` with `image` argument set
    (look at :py:meth:`from_memory` method).
    """
    def __init__(self, buf, base=0, regions=None, image=False):
        super(ProcessMemoryPE, self).__init__(buf, base=base, regions=regions)
        self._pe = None
        self._imgend = None
        if image:
            self._load_image()

    @classmethod
    def from_memory(cls, memory, base=None, image=False):
        """
        Creates ProcessMemoryPE instance from ProcessMemory object.

        :param memory: ProcessMemory object containing PE image
        :type memory: :class:`ProcessMemory`
        :param base: Virtual address where PE image is located (default: beginning of procmem)
        :param image: True if memory contains EXE file instead of memory-mapped PE (default: False)
        :rtype: :class:`ProcessMemory`

        When image is True - PE file will be loaded under location specified in PE header
        (pe.optional_header.ImageBase). :class:`ProcessMemoryPE` object created that way contains only memory regions
        created during load (all other data will be wiped out). If image contains relocation info, relocations will be
        applied using :py:meth:`pefile.relocate_image` method.
        """
        copied = cls(memory.m, base=base or memory.imgbase, regions=memory.regions, image=image)
        copied.f = memory.f
        return copied

    def _load_image(self):
        # Load PE data from imgbase offset
        offset = self.v2p(self.imgbase)
        self.m = self.m[offset:]
        pe = PE(data=self.m, fast_load=True)
        # Reset regions
        self.imgbase = pe.optional_header.ImageBase
        self.regions = [
            Region(self.imgbase, 0x1000, 0, 0, 0, 0)
        ]
        # Apply relocations
        if hasattr(pe.pe, "DIRECTORY_ENTRY_BASERELOC"):
            pe.pe.relocate_image(self.imgbase)
        # Load image sections
        for section in pe.sections:
            if section.SizeOfRawData > 0:
                self.regions.append(Region(
                    self.imgbase + section.VirtualAddress,
                    section.SizeOfRawData,
                    0, 0, 0,
                    section.PointerToRawData
                ))

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

    def store(self, image=False):
        """TODO"""
        raise NotImplementedError()

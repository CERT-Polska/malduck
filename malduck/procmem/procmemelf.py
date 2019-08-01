from .region import Region
from .procmem import ProcessMemory

import elftools
import elftools.elf.elffile
import io


class ProcessMemoryELF(ProcessMemory):
    """
    Representation of memory-mapped ELF file

    Short name: `procmemelf`

    ELF files can be read directly using inherited :py:meth:`ProcessMemory.from_file` with `image` argument set
    (look at :py:meth:`from_memory` method).
    """
    def __init__(self, buf, base=0, regions=None, image=False):
        super(ProcessMemoryELF, self).__init__(buf, base=base, regions=regions)
        self._elf = None
        self._imgend = None
        if image:
            self._load_image(page_size=0x1000)

    @classmethod
    def from_memory(cls, memory, base=None, image=False):
        """
        Creates ProcessMemoryELF instance from ProcessMemory object.

        :param memory: ProcessMemory object containing ELF image
        :type memory: :class:`ProcessMemory`
        :param base: Virtual address where ELF image is located (default: beginning of procmem)
        :param image: True if memory contains ELF executable file instead of memory-mapped ELF (default: False)
        :param detect_image: ProcessMemoryELF automatically detect whether image or memory-mapped ELF is loaded
                             (default: False)
        :rtype: :class:`ProcessMemory`

        When image is True - ELF file will be loaded under location specified in program header
        (elf.get_segment(0).header['p_vaddr']). :class:`ProcessMemoryELF` object created that way contains only memory regions
        created during load (all other data will be wiped out).
        """
        copied = cls(memory.m, base=base or memory.imgbase, regions=memory.regions, image=image)
        copied.f = memory.f
        return copied

    def _elf_direct_load(self, fast_load=True):
        offset = self.v2p(self.imgbase)
        # Stream required for ELFFile()
        stream = io.BytesIO(self.readp(offset))
        elf = elftools.elf.elffile.ELFFile(stream)
        return elf

    def _load_image(self, page_size=None):
        # Reset regions
        self.imgbase = None
        self.regions = []
        # Load image segments
        for segment in self.elf.iter_segments():
            if segment.header['p_type'] == 'PT_LOAD':
                if segment.header['p_offset'] == 0:
                    self.imgbase = segment.header['p_vaddr']  # virtual address of ELF file header
                if page_size is None:
                    presegment_len = 0
                    postsegment_len = 0
                else:
                    presegment_len = segment.header['p_vaddr'] % page_size
                    postsegment_len = page_size - (segment.header['p_vaddr'] + segment.header['p_filesz']) % page_size
                self.regions.append(Region(
                    segment.header['p_vaddr'] - presegment_len,
                    segment.header['p_filesz'] + presegment_len + postsegment_len,
                    0,
                    segment.header['p_type'],
                    0,  # TODO: protect flags
                    segment.header['p_offset'] - presegment_len
                ))

    @property
    def elf(self):
        """Related :class:`ELFFile` object"""
        if not self._elf:
            self._elf = self._elf_direct_load(fast_load=False)
        return self._elf

    @property
    def imgend(self):
        """Address where ELF image ends"""
        if not self._imgend:
            lastSegment = self.elf.get_segment(self.elf.num_segment()-1)
            self._imgend = lastSegment.header['p_vaddr'] + lastSegment.header['p_memsz']
        return self._imgend


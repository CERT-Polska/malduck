import elftools
import elftools.elf.elffile
import io

from typing import List, Optional

from .binmem import ProcessMemoryBinary
from .procmem import ProcessMemoryBuffer
from .region import Region

__all__ = ["ProcessMemoryELF", "procmemelf"]


class ProcessMemoryELF(ProcessMemoryBinary):
    """
    Representation of memory-mapped ELF file

    Short name: `procmemelf`

    ELF files can be read directly using inherited :py:meth:`ProcessMemory.from_file` with `image` argument set
    (look at :py:meth:`from_memory` method).
    """

    __magic__ = b"\x7fELF"

    def __init__(
        self,
        buf: ProcessMemoryBuffer,
        base: int = 0,
        regions: Optional[List[Region]] = None,
        image: bool = False,
        detect_image: bool = False,
    ) -> None:
        self._elf = None
        super().__init__(
            buf, base=base, regions=regions, image=image, detect_image=detect_image
        )

    def _elf_direct_load(self) -> elftools.elf.elffile.ELFFile:
        offset = self.v2p(self.imgbase)
        if offset is None:
            raise RuntimeError("imgbase out of regions")
        # Stream required for ELFFile()
        stream = io.BytesIO(self.readp(offset))
        elf = elftools.elf.elffile.ELFFile(stream)
        # Try to iter_segments to check whether ELFFile is really correct
        list(elf.iter_segments())
        return elf

    def is_valid(self) -> bool:
        if self.readv(self.imgbase, 4) != self.__magic__:
            return False
        try:
            self._elf_direct_load()
            return True
        except Exception:
            return False

    def _reload_as_image(self) -> None:
        page_size = 0x1000
        # Reset regions
        imgbase = None
        regions = []
        # Load image segments
        for segment in self.elf.iter_segments():
            if segment.header["p_type"] == "PT_LOAD":
                if segment.header["p_offset"] == 0:
                    # virtual address of ELF file header
                    imgbase = segment.header["p_vaddr"]
                if page_size is None:
                    presegment_len = 0
                    postsegment_len = 0
                else:
                    presegment_len = segment.header["p_vaddr"] % page_size
                    postsegment_len = (
                        page_size
                        - (segment.header["p_vaddr"] + segment.header["p_filesz"])
                        % page_size
                    )
                regions.append(
                    Region(
                        segment.header["p_vaddr"] - presegment_len,
                        segment.header["p_filesz"] + presegment_len + postsegment_len,
                        0,
                        segment.header["p_type"],
                        0,  # TODO: protect flags
                        segment.header["p_offset"] - presegment_len,
                    )
                )
        if len(regions) == 0:
            raise elftools.elf.elffile.ELFError("No regions in ELF file!")
        if imgbase is None:
            raise elftools.elf.elffile.ELFError("Can't find ELF image base!")
        self.imgbase = imgbase
        self.regions = regions

    @property
    def elf(self) -> elftools.elf.elffile.ELFFile:
        """Related :class:`ELFFile` object"""
        if not self._elf:
            self._elf = self._elf_direct_load()
        return self._elf

    def is_image_loaded_as_memdump(self):
        raise NotImplementedError()

    @property
    def imgend(self) -> int:
        """Address where ELF image ends"""
        lastSegment = self.elf.get_segment(self.elf.num_segment() - 1)
        return lastSegment.header["p_vaddr"] + lastSegment.header["p_memsz"]


procmemelf = ProcessMemoryELF

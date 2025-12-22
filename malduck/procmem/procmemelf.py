import io
from typing import List, Optional

import elftools
import elftools.elf.elffile

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
        self._elf: Optional[elftools.elf.elffile.ELFFile] = None
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
        # For embedded ELFs, segment offsets are relative to ELF start, not buffer start
        elf_base_offset = self.v2p(self.imgbase)
        if elf_base_offset is None:
            raise RuntimeError("imgbase out of regions")

        # Collect PT_LOAD segments (only these are mapped into memory)
        segments = []
        for segment in self.elf.iter_segments():
            if segment.header["p_type"] == "PT_LOAD" and segment.header["p_filesz"] > 0:
                segments.append({
                    "vaddr": segment.header["p_vaddr"],
                    "filesz": segment.header["p_filesz"],
                    "offset": segment.header["p_offset"],
                    "type": segment.header["p_type"],
                })

        if len(segments) == 0:
            raise elftools.elf.elffile.ELFError("No regions in ELF file!")

        # Sort by file offset to process gaps between segments
        segments.sort(key=lambda s: s["offset"])

        # imgbase = VA where file offset 0 would be mapped
        # Uses ELF invariant: p_vaddr and p_offset have same alignment
        first_seg = segments[0]
        imgbase = first_seg["vaddr"] - first_seg["offset"]

        regions = []

        # If first segment doesn't start at offset 0, create region for ELF header
        if first_seg["offset"] > 0:
            regions.append(
                Region(imgbase, first_seg["offset"], 0, 0, 0, elf_base_offset)
            )

        for i, seg in enumerate(segments):
            # Extend region to next segment to expose gaps (may contain hidden data)
            if i + 1 < len(segments):
                region_size = segments[i + 1]["offset"] - seg["offset"]
            else:
                region_size = seg["filesz"]

            regions.append(
                Region(
                    seg["vaddr"],
                    region_size,
                    0,
                    seg["type"],
                    0,
                    elf_base_offset + seg["offset"],
                )
            )

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
        lastSegment = self.elf.get_segment(self.elf.num_segments() - 1)
        return lastSegment.header["p_vaddr"] + lastSegment.header["p_memsz"]


procmemelf = ProcessMemoryELF

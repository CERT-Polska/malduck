from typing import List, Optional

from ..dnpe import DnPE
from .binmem import ProcessMemoryBuffer
from .procmempe import ProcessMemoryPE
from .region import Region

__all__ = ["ProcessMemoryDnPE", "procmemdnpe"]


class ProcessMemoryDnPE(ProcessMemoryPE):

    __magic__ = b"MZ"

    def __init__(
        self,
        buf: ProcessMemoryBuffer,
        base: int = 0,
        regions: Optional[List[Region]] = None,
        image: bool = False,
        detect_image: bool = False,
    ) -> None:
        self._pe: Optional[DnPE] = None
        super(ProcessMemoryPE, self).__init__(
            buf, base=base, regions=regions, image=image, detect_image=detect_image
        )

    def _pe_direct_load(self, fast_load: bool = True) -> DnPE:
        offset = self.v2p(self.imgbase)
        if offset is None:
            raise ValueError("imgbase out of regions")
        # Expected m type: bytearray
        m = bytearray(self.readp(offset))
        pe = DnPE(data=m, fast_load=fast_load)
        return pe

    def is_valid(self) -> bool:
        if self.readv(self.imgbase, 2) != self.__magic__:
            return False
        pe_offs = self.uint32v(self.imgbase + 0x3C)
        if pe_offs is None:
            return False
        if self.readv(self.imgbase + pe_offs, 2) != b"PE":
            return False
        try:
            dn = DnPE(self)
            if not hasattr(dn, "net"):
                return False

            return True
        except Exception:
            return False

    @property
    def pe(self) -> DnPE:
        """Related :class:`PE` object"""
        if self._pe is None:
            self._pe = DnPE(self)
        return self._pe


procmemdnpe = ProcessMemoryDnPE

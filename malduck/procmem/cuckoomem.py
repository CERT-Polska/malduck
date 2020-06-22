import struct

from typing import Optional

from .procmem import ProcessMemory, ProcessMemoryBuffer
from .region import Region

__all__ = ["CuckooProcessMemory", "cuckoomem"]


class CuckooProcessMemory(ProcessMemory):
    """Wrapper object to operate on process memory dumps in Cuckoo 2.x format."""

    def __init__(
        self, buf: ProcessMemoryBuffer, base: Optional[int] = None, **_
    ) -> None:
        super(CuckooProcessMemory, self).__init__(buf)
        ptr = 0
        self.regions = []

        while ptr < self.length:
            hdr = self.readp(ptr, 24)
            if not hdr:
                break

            addr, size, state, typ, protect = struct.unpack("QIIII", hdr)
            ptr += 24

            self.regions.append(Region(addr, size, state, typ, protect, ptr))
            ptr += size
        if base is None:
            if self.regions:
                self.imgbase = self.regions[0].addr
            else:
                self.imgbase = 0


cuckoomem = CuckooProcessMemory

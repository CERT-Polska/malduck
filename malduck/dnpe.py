import dnfile

from typing import Union, Optional, List

from .procmem import ProcessMemory
from .pe import MemoryPEData, PE


__all__ = ["dnpe", "DnPE", "MemoryDnPEData"]


class MemoryDnPEData(MemoryPEData):
    def __init__(self, memory: ProcessMemory, fast_load: bool) -> None:
        self.memory = memory
        # Preload headers
        self.pe = dnfile.dnPE(data=self, fast_load=True)
        if not fast_load:
            self.pe.full_load()


class DnPE(PE):
    def __init__(
        self, data: Union[ProcessMemory, bytes], fast_load: bool = False
    ) -> None:

        if isinstance(data, ProcessMemory):
            self.pe = MemoryDnPEData(data, fast_load).pe
        else:
            self.pe = dnfile.dnPE(data=data, fast_load=fast_load)

    @property
    def us(self) -> dnfile.stream.UserStringHeap:
        return self.pe.net.metadata.streams.get(b"#US", None)

    def us_string(self, offset: int) -> Optional[dnfile.stream.UserString]:
        if not self.us or self.us.sizeof() == 0:
            return None

        if offset > self.us.sizeof():
            return None

        buffer, read_length = self.us.get_with_size(offset)
        try:
            us_string = dnfile.stream.UserString(buffer)
        except UnicodeDecodeError:
            return None

        return us_string

    def us_strings(self) -> Optional[List[dnfile.stream.UserString]]:
        if not self.us or self.us.sizeof() == 0:
            return None

        strings = []
        offset = 1
        while offset < self.us.sizeof():
            us_string = self.us_string(offset)
            if not us_string:
                break

            strings.append(us_string)

        return strings


dnpe = DnPE

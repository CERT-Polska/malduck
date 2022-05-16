from typing import Any, Iterator, List, Optional, Union

import dnfile

from .pe import PE, MemoryPEData
from .procmem import ProcessMemory

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
    def dn_metadata(self) -> Optional[dnfile.stream.MetaDataTables]:
        return self.pe.net.metadata

    @property
    def dn_strings(self) -> Optional[dnfile.stream.StringsHeap]:
        return self.pe.net.strings

    @property
    def dn_user_strings(self) -> Optional[dnfile.stream.UserStringHeap]:
        return self.pe.net.user_strings

    @property
    def dn_guid(self) -> Optional[dnfile.stream.GuidHeap]:
        return self.pe.net.guids

    @property
    def dn_mdtables(self) -> Optional[dnfile.stream.MetaDataTables]:
        return self.pe.net.mdtables

    @property
    def dn_resources(self) -> List:
        return self.pe.net.resources

    @property
    def dn_flags(self) -> Any:
        return self.pe.net.flags

    def dn_user_string(
        self, index: int, encoding="utf-16"
    ) -> Optional[dnfile.stream.UserString]:
        if not self.dn_user_strings or self.dn_user_strings.sizeof() == 0:
            return None

        try:
            us_string = self.dn_user_strings.get_us(index, encoding=encoding)
        except UnicodeDecodeError:
            return None

        return us_string

    def dn_iterate_resources(self) -> Iterator:
        for resource in self.dn_resources:
            if isinstance(resource.data, bytes):
                yield resource

            elif isinstance(resource.data, dnfile.resource.ResourceSet):
                if not resource.data.entries:
                    continue

                for entry in resource.data.entries:
                    if entry.data:
                        yield entry.data


dnpe = DnPE

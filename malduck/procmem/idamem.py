from .procmem import ProcessMemory
from .region import Region

try:
    import idautils
    import idc
    import ida_bytes

    IDAPYTHON = 1
except ImportError:
    IDAPYTHON = 0

__all__ = ["IDAProcessMemory", "idamem"]


class IDAVM(object):
    def __init__(self, idamem):
        self.idamem = idamem

    def _get_ea_range(self, item):
        if isinstance(item, slice):
            offset = item.start or 0
            length = (item.stop or len(self)) - offset
        else:
            offset = item
            length = 1
        for region in self.idamem.regions:
            if region.offset < offset + length and offset < region.end_offset:
                ea_start = min(max(region.p2v(offset), region.addr), region.end)
                ea_end = min(max(region.p2v(offset + length), region.addr), region.end)
                yield (ea_start, ea_end)

    def __setitem__(self, item, value):
        value_bytes = iter(value)
        for ea_start, ea_end in self._get_ea_range(item):
            for ea in range(ea_start, ea_end):
                try:
                    ida_bytes.patch_byte(ea, next(value_bytes))
                except StopIteration:
                    return

    def __getitem__(self, item):
        data = []
        for ea_start, ea_end in self._get_ea_range(item):
            data.append(idc.get_bytes(ea_start, ea_end - ea_start))
        return b"".join(data)

    def __len__(self):
        return self.idamem.regions[-1].end_offset


class IDAProcessMemory(ProcessMemory):
    """
    ProcessMemory representation operating in IDAPython context [BETA]
    """

    def __init__(self):
        if not IDAPYTHON:
            raise RuntimeError(
                "This class is intended to work only in IDAPython context"
            )
        regions = []
        for seg in idautils.Segments():
            off = 0 if not regions else regions[-1].end_offset
            region = Region(seg, idc.get_segm_end(seg) - seg, 0, 0, 0, off)
            regions.append(region)
        super().__init__(IDAVM(self), regions=regions)


idamem = IDAProcessMemory

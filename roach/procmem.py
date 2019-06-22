# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import mmap
import re
import struct

try:
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False

from roach.disasm import disasm
from roach.string.ops import utf16z
from roach.string.bin import uint8, uint16, uint32, uint64

PAGE_READONLY = 0x00000002
PAGE_READWRITE = 0x00000004
PAGE_WRITECOPY = 0x00000008
PAGE_EXECUTE = 0x00000010
PAGE_EXECUTE_READ = 0x00000020
PAGE_EXECUTE_READWRITE = 0x00000040
PAGE_EXECUTE_WRITECOPY = 0x00000080

page_access = {
    PAGE_READONLY: "r",
    PAGE_READWRITE: "rw",
    PAGE_WRITECOPY: "rwc",
    PAGE_EXECUTE: "rx",
    PAGE_EXECUTE_READ: "rx",
    PAGE_EXECUTE_READWRITE: "rwx",
    PAGE_EXECUTE_WRITECOPY: "rwxc",
}


class Region(object):
    def __init__(self, addr, size, state, type_, protect, offset):
        self.addr = addr
        self.size = size
        self.end = addr + size
        self.state = state
        self.type_ = type_
        self.protect = protect
        self.offset = offset

    def to_json(self):
        return {
            "addr": "0x%08x" % self.addr,
            "end": "0x%08x" % (self.addr + self.size),
            "size": self.size,
            "state": self.state,
            "type": self.type_,
            "protect": page_access.get(self.protect),
            "offset": self.offset,
        }

    def __cmp__(self, other):
        if not isinstance(other, Region):
            raise RuntimeError("not a region object!")

        # TODO Include the offset in this comparison?
        return not (
            self.addr == other.addr and self.size == other.size and
            self.state == other.state and self.type_ == other.type_ and
            self.protect == other.protect
        )


class ProcessMemory(object):
    """Basic virtual memory representation"""
    def __init__(self, buf, base=0, regions=None):
        self.m = buf
        self.imgbase = base

        if regions is not None:
            self.regions = regions
        else:
            self.regions = [Region(base, self.length, 0, 0, PAGE_EXECUTE_READWRITE, 0)]

    @classmethod
    def from_file(cls, f, **kwargs):
        try:
            # psrok1: allow copy-on-write
            if hasattr(mmap, "MAP_PRIVATE"):
                access = mmap.MAP_PRIVATE
            elif hasattr(mmap, "ACCESS_COPY"):
                access = mmap.ACCESS_COPY
            else:
                raise RuntimeError("mmap is not supported on your OS")

            m = mmap.mmap(f.fileno(), 0, access=access)
            return cls(m, **kwargs)
        except RuntimeError:
            return cls(f.read(), **kwargs)

    @classmethod
    def from_memory(cls, memory):
        return cls(memory.m, base=memory.imgbase, regions=memory.regions)

    @property
    def length(self):
        if hasattr(self.m, "size"):
            return self.m.size()
        else:
            return len(self.m)

    def v2p(self, addr):
        """Virtual address to physical offset translation."""
        for region in self.regions:
            if region.addr <= addr < region.end:
                return region.offset + addr - region.addr

    def p2v(self, off):
        """Physical offset to virtual address translation."""
        for region in self.regions:
            if region.offset <= off < region.offset + region.size:
                return region.addr + off - region.offset

    def addr_range(self, addr):
        """Returns a (start, end) range for an address."""
        for region in self.regions:
            if region.addr <= addr < region.end:
                return region.addr, region.size

    def addr_region(self, addr):
        for region in self.regions:
            if region.addr <= addr < region.end:
                return region

    def read(self, offset, length):
        """Read a chunk of memory from the memory dump."""
        return self.m[offset:offset+length]

    def readv(self, addr, length):
        """Reads a continuous buffer with address and length."""
        ret = []
        while length:
            r = self.addr_range(addr)
            if not r:
                break
            a, l = r
            l = min(a + l - addr, length)
            ret.append(self.read(self.v2p(addr), l))
            addr, length = addr + l, length - l
        return "".join(ret)

    def read_until(self, addr, s=None):
        """Reads a continuous buffer with address until the stop marker."""
        ret = []
        while True:
            r = self.addr_range(addr)
            if not r:
                break
            a, l = r
            l = a + l - addr
            buf = self.read(self.v2p(addr), l)
            if s and s in buf:
                ret.append(buf[:buf.index(s)])
                break
            ret.append(buf)
            addr = addr + l
        return "".join(ret)

    def uint8p(self, offset):
        """Read unsigned 8-bit value at offset."""
        return uint8(self.read(offset, 1))

    def uint16p(self, offset):
        """Read unsigned 16-bit value at offset."""
        return uint16(self.read(offset, 2))

    def uint32p(self, offset):
        """Read unsigned 32-bit value at offset."""
        return uint32(self.read(offset, 4))

    def uint64p(self, offset):
        """Read unsigned 64-bit value at offset."""
        return uint64(self.read(offset, 8))

    def uint8v(self, addr):
        """Read unsigned 8-bit value at address."""
        return uint8(self.readv(addr, 1))

    def uint16v(self, addr):
        """Read unsigned 16-bit value at address."""
        return uint16(self.readv(addr, 2))

    def uint32v(self, addr):
        """Read unsigned 32-bit value at address."""
        return uint32(self.readv(addr, 4))

    def uint64v(self, addr):
        """Read unsigned 64-bit value at address."""
        return uint64(self.readv(addr, 8))

    def asciiz(self, addr):
        """Read a nul-terminated ASCII string at address."""
        return self.read_until(addr, "\x00")

    def utf16z(self, addr):
        """Read a nul-terminated UTF-16 string at address."""
        ret = []
        while True:
            r = self.addr_range(addr)
            if not r:
                break
            a, l = r
            l = a + l - addr
            buf = self.read(self.v2p(addr), l)

            utf16 = utf16z(buf)
            ret.append(utf16)
            if utf16 != buf:
                break
            addr = addr + l
        return "".join(ret)

    def regexp(self, query, offset=0, length=0):
        """Performs a regex on the file """
        if offset and length:
            chunk = self.m[offset:offset+length]
        else:
            chunk = self.m
        for entry in re.finditer(query, chunk, re.DOTALL):
            yield offset + entry.start()

    def regexv(self, query, addr=None, length=None):
        """Performs a regex on the file """
        if addr and length:
            offset, end = self.v2p(addr), self.v2p(addr + length)
            length = end - offset
        else:
            offset = length = 0
        for offset in self.regexp(query, offset, length):
            addr = self.p2v(offset)
            if addr:
                yield addr

    def disasmv(self, addr, size):
        return disasm(self.readv(addr, size), addr)

    def _findbytes(self, regex, query, addr, length):
        def byte2re(b):
            hexrange = "0123456789abcdef?"
            if len(b) != 2:
                raise ValueError("Length of query should be even")
            first, second = b
            if first not in hexrange or second not in hexrange:
                raise ValueError("Incorrect query - only 0-9a-fA-F? chars are allowed")
            if b == "??":
                return r"."
            if first == "?":
                return r"[{}]".format(''.join(r"\x"+ch+second for ch in "0123456789abcdef"))
            if second == "?":
                return r"[\x{first}0-\x{first}f]".format(first=first)
            return r"\x"+b
        query = ''.join(query.lower().split(" "))
        rquery = ''.join(map(byte2re, [query[i:i+2] for i in range(0, len(query), 2)]))
        return regex(rquery, addr, length)

    def findbytesp(self, query, offset=0, length=0):
        """Search for byte sequences (4? AA BB ?? DD). Uses regexp internally"""
        return self._findbytes(self.regexp, query, offset, length)

    def findbytesv(self, query, addr=None, length=None):
        """Search for byte sequences (4? AA BB ?? DD). Uses regexv internally"""
        return self._findbytes(self.regexv, query, addr, length)

    def findmz(self, addr):
        """Locates the MZ header based on an address."""
        addr &= ~0xffff
        while True:
            buf = self.readv(addr, 2)
            if not buf:
                return
            if buf == "MZ":
                return addr
            addr -= 0x10000

    def dumppe(self, addr, filepath, is64bit=False):
        """Dumps a potential PE file based on the memory regions as opposed to
        the MZ/PE header, allowing potentially corrupted MZ/PE headers."""
        if not HAVE_LIEF:
            raise RuntimeError("procmem::dumppe requires lief!")

        # What can we do to improve this - generally speaking we'll almost
        # always find the .text section at offset 0x1000.
        for idx, r in enumerate(self.regions):
            if r.addr == addr + 0x1000:
                break
        else:
            return False

        pe = lief.PE.Binary(
            "sample.bin",
            lief.PE.PE_TYPE.PE32_PLUS if is64bit else lief.PE.PE_TYPE.PE32
        )

        while idx < len(self.regions)-1:
            r, r2 = self.regions[idx:idx+2]

            s = lief.PE.Section(".sec%d" % len(pe.sections))
            s.virtual_address = r.addr - addr
            s.content = bytearray(self.readv(r.addr, r.size))
            s.characteristics = (
                lief.PE.SECTION_CHARACTERISTICS.MEM_READ |
                lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE |
                lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
            )
            s = pe.add_section(s, lief.PE.SECTION_TYPES.TEXT)

            # It seems we're not interested in the next memory page.
            if r.addr + r.size != r2.addr:
                break

            idx += 1

        builder = lief.PE.Builder(pe)
        builder.build()
        builder.write(filepath)
        return True


class ProcessMemoryPE(ProcessMemory):
    """ Representation of memory-mapped PE file """
    def __init__(self, buf, base=0, regions=None, image=False):
        super(ProcessMemoryPE, self).__init__(buf, base=base, regions=regions)
        self._pe = None
        self._imgend = None
        if image:
            self._load_image()

    @classmethod
    def from_memory(cls, memory, base=None, image=False):
        return cls(memory.m, base=base or memory.imgbase, regions=memory.regions, image=image)

    def _load_image(self):
        from roach.pe import PE
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
        if not self._pe:
            from roach.pe import PE
            self._pe = PE(self)
        return self._pe

    @property
    def imgend(self):
        if not self._imgend:
            section = self.pe.sections[-1]
            self._imgend = (
                self.imgbase +
                section.VirtualAddress + section.Misc_VirtualSize
            )
        return self._imgend


class CuckooProcessMemory(ProcessMemory):
    """Wrapper object to operate on process memory dumps in Cuckoo 2.x format."""
    def __init__(self, buf):
        ptr = 0
        regions = []

        while ptr < self.length:
            hdr = buf[ptr:ptr+24]
            if not hdr:
                break

            addr, size, state, typ, protect = struct.unpack("QIIII", hdr)
            ptr += 24

            regions.append(
                Region(addr, size, state, typ, protect, ptr)
            )
            ptr += size
        super(CuckooProcessMemory, self).__init__(buf, regions=regions)

    def store(self):
        """ Stores ProcessMemory into string """
        raise NotImplementedError()

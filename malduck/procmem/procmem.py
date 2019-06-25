import mmap
import re

from .region import Region, PAGE_EXECUTE_READWRITE
from ..disasm import disasm
from ..string.bin import uint8, uint16, uint32, uint64


class ProcessMemory(object):
    """
    Basic virtual memory representation

    Short name: `procmem`

    :param buf: Object with memory contents
    :type buf: str or mmap objects (todo: memoryview and bytes support)
    :param base: Virtual address of the beginning of buf
    :type base: int, optional (default: 0)
    :param regions: Regions mapping. If set to None (default), buf is mapped into single-region with VA specified in
                    `base` argument
    :type regions: List[:class:`Region`]

    This constructor should be used only when payload is accessible as raw buffer.
    For reading payload from file: look at :py:meth:`from_file` method.
    """
    def __init__(self, buf, base=0, regions=None):
        self.f = None
        self.m = buf
        self.imgbase = base

        if regions is not None:
            self.regions = regions
        else:
            self.regions = [Region(base, self.length, 0, 0, PAGE_EXECUTE_READWRITE, 0)]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self, copy=False):
        """
        Closes opened files referenced by ProcessMemory object
        :param copy: Copy data into string before closing the mmap object (default: False)
        """
        if self.f is not None:
            if hasattr(self.m, "close"):
                if copy:
                    self.m.seek(0)
                    buf = self.m.read()
                else:
                    buf = None
                self.m.close()
                self.m = buf
            self.f.close()
            self.f = None

    @classmethod
    def from_file(cls, filename, **kwargs):
        """
        Opens file and loads its contents into ProcessMemory object
        :param filename: File name to load
        :rtype: :class:`ProcessMemory`
        """
        f = open(filename, "rb")
        try:
            # Allow copy-on-write
            if hasattr(mmap, "ACCESS_COPY"):
                m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_COPY)
            else:
                raise RuntimeError("mmap is not supported on your OS")
            memory = cls(m, **kwargs)
        except RuntimeError as e:
            # Fallback to f.read()
            memory = cls(f.read(), **kwargs)
            f.close()
            f = None
        memory.f = f
        return memory

    @classmethod
    def from_memory(cls, memory):
        """
        Makes new instance based on another ProcessMemory object.
        Useful for specialized derived classes like :class:`CuckooProcessMemory`
        :param memory: ProcessMemory object to be copied
        :type memory: :class:`ProcessMemory`
        :rtype: :class:`ProcessMemory`
        """
        copied = cls(memory.m, base=memory.imgbase, regions=memory.regions)
        copied.f = memory.f
        return copied

    @property
    def _mmaped(self):
        return isinstance(self.m, mmap.mmap)

    @property
    def length(self):
        if self._mmaped:
            return self.m.size()
        else:
            return len(self.m)

    def v2p(self, addr):
        """
        Virtual address to buffer (physical) offset translation
        :param addr: Virtual address
        :return: Buffer offset or None if virtual address is not mapped
        """
        for region in self.regions:
            if region.addr <= addr < region.end:
                return region.offset + addr - region.addr

    def p2v(self, off):
        """
        Buffer (physical) offset to virtual address translation
        :param off: Buffer offset
        :return: Virtual address or None if offset is not mapped
        """
        for region in self.regions:
            if region.offset <= off < region.offset + region.size:
                return region.addr + off - region.offset

    def addr_region(self, addr):
        """
        Returns Region object mapping specified virtual address
        :param addr: Virtual address
        :rtype: :class:`Region`
        """
        for region in self.regions:
            if region.addr <= addr < region.end:
                return region

    def iter_region(self, addr):
        """
        Returns generator of Region objects starting at virtual address
        :param addr: Virtual address
        :rtype: Iterator[:class:`Region`]
        """
        start = False
        for region in self.regions:
            if region.addr <= addr < region.end:
                start = True
            if start:
                yield region

    def readp(self, offset, length=None):
        """
        Read a chunk of memory from the specified buffer offset.

        .. warning::

           Family of '*p' methods doesn't care about continuity of regions.
           Use :py:meth:`p2v` and :py:meth:`readv` if you want to operate on continuous regions only

        :param offset: Buffer offset
        :param length: Length of chunk (optional)
        :return: Chunk from specified location
        :rtype: str
        """
        if length is None:
            return self.m[offset:]
        else:
            return self.m[offset:offset+length]

    def readv_regions(self, addr, length=None):
        """
        Generate chunks of memory from next continuous regions, starting from the specified virtual address,
        until specified length of read data is reached.

        Used internally.

        :param addr: Virtual address
        :param length: Size of memory to read (optional)
        :rtype: Iterator[str]
        """
        regions = self.iter_region(addr)
        prev_region = None
        while length or length is None:
            region = next(regions)
            if prev_region and prev_region.end != region.addr:
                # Gap between regions - break
                break
            # Get starting region offset
            rel_offs = addr - region.addr
            # ... and how many bytes we need to read
            rel_length = region.size - rel_offs
            if length is not None and length < rel_length:
                rel_length = length
            # Yield read chunk
            yield self.readp(region.offset + rel_offs, rel_length)
            # Go to next region
            if length is not None:
                length -= rel_length
            addr += rel_length
            prev_region = region

    def readv(self, addr, length=None):
        """
        Read a chunk of memory from the specified virtual address
        :param addr: Virtual address
        :param length: Length of chunk (optional)
        :return: Chunk from specified location
        :rtype: str
        """
        return ''.join(self.readv_regions(addr, length))

    def readv_until(self, addr, s=None):
        """
        Read a chunk of memory until the stop marker
        :param addr: Virtual address
        :param s: Stop marker
        :rtype: str
        """
        ret = []
        for chunk in self.readv_regions(addr):
            if s in chunk:
                ret.append(chunk[:chunk.index(s)])
                break
            ret.append(chunk)
        return "".join(ret)

    def patchp(self, offset, buf):
        """
        Patch bytes under specified offset

        .. warning::

           Family of '*p' methods doesn't care about continuity of regions.
           Use :py:meth:`p2v` and :py:meth:`patchv` if you want to operate on continuous regions only

        :param offset: Buffer offset
        :param buf: Buffer with patch to apply
        """
        length = len(buf)
        if self._mmaped:
            self.m[offset:offset + length] = buf
        else:
            self.m = self.m[:offset] + buf + self.m[offset + length:]

    def patchv(self, addr, buf):
        """
        Patch bytes under specified virtual address
        :param addr: Virtual address
        :param buf: Buffer with patch to apply
        """
        region = self.addr_region(addr)
        # Bound check
        if region.end > (addr + len(buf)):
            raise ValueError("Cross-region patching is not supported")
        return self.patchp(region.offset + addr - region.addr, buf)

    def uint8p(self, offset):
        """Read unsigned 8-bit value at offset."""
        return uint8(self.readp(offset, 1))

    def uint16p(self, offset):
        """Read unsigned 16-bit value at offset."""
        return uint16(self.readp(offset, 2))

    def uint32p(self, offset):
        """Read unsigned 32-bit value at offset."""
        return uint32(self.readp(offset, 4))

    def uint64p(self, offset):
        """Read unsigned 64-bit value at offset."""
        return uint64(self.readp(offset, 8))

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
        return self.readv_until(addr, "\x00")

    def utf16z(self, addr):
        """Read a nul-terminated UTF-16 string at address."""
        return self.readv_until(addr, "\x00\x00")

    def regexp(self, query, offset=0, length=None):
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
        """
        Search for byte sequences (4? AA BB ?? DD). Uses regexp internally
        :param query: Sequence of wildcarded hexadecimal bytes, separated by spaces
        :param offset: Buffer offset where searching will be started
        :param length: Length of searched area
        :return: Iterator returning next offsets
        :rtype: Iterator[int]
        """
        return self._findbytes(self.regexp, query, offset, length)

    def findbytesv(self, query, addr=None, length=None):
        """
        Search for byte sequences (4? AA BB ?? DD). Uses regexv internally
        :param query: Sequence of wildcarded hexadecimal bytes, separated by spaces
        :param offset: Virtual address where searching will be started
        :param length: Length of searched area
        :return: Iterator returning found virtual addresses
        :rtype: Iterator[int]

        Usage example:

        .. code-block:: python

            from malduck import hex

            findings = []

            for va in mem.findbytesv("4? AA BB ?? DD"):
                if hex(mem.readv(va, 5)) == "4aaabbccdd":
                    findings.append(va)
        """
        return self._findbytes(self.regexv, query, addr, length)

    def findmz(self, addr):
        """
        Tries to locate MZ header based on address inside PE image
        :param addr: Virtual address inside image
        :return: Virtual address of found MZ header or None
        """
        addr &= ~0xfff
        while True:
            buf = self.readv(addr, 2)
            if not buf:
                return
            if buf == "MZ":
                return addr
            addr -= 0x1000

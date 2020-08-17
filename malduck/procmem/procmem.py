import mmap
import re

from typing import BinaryIO, List, Optional, Union, cast

from .region import Region, PAGE_EXECUTE_READWRITE
from ..disasm import disasm
from ..string.bin import uint8, uint16, uint32, uint64, int8, int16, int32, int64
from ..string.ops import utf16z
from ..yara import Yara, YaraString

__all__ = ["ProcessMemory", "procmem"]

ProcessMemoryBuffer = Union[bytes, bytearray, mmap.mmap]


class ProcessMemory:
    """
    Basic virtual memory representation

    Short name: `procmem`

    :param buf: Object with memory contents
    :type buf: bytes, mmap, memoryview or bytearray object
    :param base: Virtual address of the region of interest (or beginning of buf when no regions provided)
    :type base: int, optional (default: 0)
    :param regions: Regions mapping. If set to None (default), buf is mapped into single-region with VA specified in
                    `base` argument
    :type regions: List[:class:`Region`]

    Let's assume that `notepad.exe_400000.bin` contains raw memory dump starting at 0x400000 base address. We can
    easily load that file to :class:`ProcessMemory` object, using :py:meth:`from_file` method:

    .. code-block:: python

        from malduck import procmem

        with procmem.from_file("notepad.exe_400000.bin", base=0x400000) as p:
            mem = p.readv(...)
            ...

    If your data are loaded yet into buffer, you can directly use `procmem` constructor:

    .. code-block:: python

        from malduck import procmem

        with open("notepad.exe_400000.bin", "rb") as f:
            payload = f.read()

        p = procmem(payload, base=0x400000)

    Then you can work with PE image contained in dump by creating :class:`ProcessMemoryPE` object, using its
    :py:meth:`from_memory` constructor method

    .. code-block:: python

        from malduck import procmem

        with open("notepad.exe_400000.bin", "rb") as f:
            payload = f.read()

        p = procmem(payload, base=0x400000)
        ppe = procmempe.from_memory(p)
        ppe.pe.resource("NPENCODINGDIALOG")

    If you want to load PE file directly and work with it in a similar way as with memory-mapped files, just use
    `image` parameter. It also works with :py:meth:`ProcessMemoryPE.from_memory` for embedded binaries. Your file
    will be loaded and relocated in similar way as it's done by Windows loader.

    .. code-block:: python

        from malduck import procmempe

        with procmempe.from_file("notepad.exe", image=True) as p:
            p.pe.resource("NPENCODINGDIALOG")
    """

    def __init__(self, buf, base=0, regions=None, **_):
        self.opened_file: Optional[BinaryIO] = None
        self.mapped_memory: Optional[mmap.mmap] = None
        self.memory: Optional[bytearray] = None

        if isinstance(buf, mmap.mmap):
            self.mapped_memory = buf
        elif isinstance(buf, bytes):
            self.memory = bytearray(buf)
        elif isinstance(buf, bytearray):
            self.memory = buf
        else:
            raise TypeError(
                "Wrong buffer type - must be bytes, bytearray or mmap object"
            )

        self.imgbase = base

        if regions is not None:
            self.regions = regions
        else:
            self.regions = [Region(base, self.length, 0, 0, PAGE_EXECUTE_READWRITE, 0)]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @property
    def m(self):
        memory = (
            cast(bytearray, self.mapped_memory)
            if self.mapped_memory is not None
            else self.memory
        )
        if memory is None:
            raise RuntimeError("ProcessMemory object is invalidated")
        return memory

    def close(self, copy=False):
        """
        Closes opened files referenced by ProcessMemory object owned by this object.

        If copy is False (default): invalidates the object.

        :param copy: Copy data into string before closing the mmap object (default: False)
        :type copy: bool
        """
        if self.mapped_memory is None:
            # Nothing to close
            return

        if copy:
            # Get object contents from mapped_memory
            self.mapped_memory.seek(0)
            contents = self.mapped_memory.read()
            buf: Optional[bytearray] = bytearray(contents)
        else:
            # Invalidate object
            buf = None

        # If self.opened_file is not None: mapped_memory is owned by this ProcessMemory object
        # We should close all descriptors
        if self.opened_file is not None:
            self.mapped_memory.close()
            self.opened_file.close()
        # In both cases: nullify all references and set memory to buf
        self.mapped_memory = None
        self.opened_file = None
        self.memory = buf

    @classmethod
    def from_file(cls, filename, **kwargs):
        """
        Opens file and loads its contents into ProcessMemory object

        :param filename: File name to load
        :rtype: :class:`ProcessMemory`

        It's highly recommended to use context manager when operating on files:

        .. code-block:: python

            from malduck import procmem

            with procmem.from_file("binary.dmp") as p:
                mem = p.readv(...)
                ...
        """
        file = open(filename, "rb")
        try:
            # Allow copy-on-write
            if hasattr(mmap, "ACCESS_COPY"):
                m = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_COPY)
            else:
                raise RuntimeError("mmap is not supported on your OS")
            memory = cls(m, **kwargs)
        except RuntimeError:
            # Fallback to file.read()
            memory = cls(file.read(), **kwargs)
            file.close()
            memory.opened_file = None
        else:
            memory.opened_file = file
        return memory

    @classmethod
    def from_memory(cls, memory, base=None, **kwargs):
        """
        Makes new instance based on another ProcessMemory object.

        Useful for specialized derived classes like :class:`CuckooProcessMemory`

        :param memory: ProcessMemory object to be copied
        :type memory: :class:`ProcessMemory`
        :param base: Virtual address of region of interest (imgbase)
        :type base: int (optional, default is provided by specialized class)
        :rtype: :class:`ProcessMemory`
        """
        copied = cls(
            memory.m, base=base or memory.imgbase, regions=memory.regions, **kwargs
        )
        return copied

    @property
    def length(self):
        """
        Returns length of raw memory contents
        :rtype: int
        """
        if self.mapped_memory is not None:
            return self.mapped_memory.size()
        elif self.memory is not None:
            return len(self.memory)
        else:
            return 0

    def iter_regions(
        self, addr=None, offset=None, length=None, contiguous=False, trim=False
    ):
        """
        Iterates over Region objects starting at provided virtual address or offset

        This method is used internally to enumerate regions using provided strategy.

        .. warning::
            If starting point is not provided, iteration will start from the first mapped region. This could
            be counter-intuitive when length is set. It literally means "get <length> of mapped bytes".
            If you want to look for regions from address 0, you need to explicitly provide this address as an argument.

        .. versionadded:: 3.0.0

        :param addr: Virtual address of starting point
        :type addr: int (default: None)
        :param offset: Offset of starting point, which will be translated to virtual address
        :type offset: int (default: None)
        :param length: Length of queried range in VM mapping context
        :type length: int (default: None, unlimited)
        :param contiguous: If True, break after first gap. Starting point must be inside mapped region.
        :type contiguous: bool (default: False)
        :param trim: Trim Region objects to range boundaries (addr, addr+length)
        :type trim: bool (default: False)
        :rtype: Iterator[:class:`Region`]
        """
        if addr is not None and offset is not None:
            raise ValueError(
                "'addr' and 'offset' arguments should be provided exclusively"
            )
        if addr is None and offset is None and contiguous:
            raise ValueError(
                "Starting point (addr or offset) must be provided for contiguous regions"
            )
        if length and length < 0:
            raise ValueError("Length can't be less than 0")
        # No length, no problem
        if length == 0:
            return
        # If we don't have starting point provided: first region is the
        # starting point
        if addr is None and offset is None:
            addr = self.regions[0].addr
        # Skipping regions before starting point
        for region_idx, region in enumerate(self.regions):
            if (addr is not None and addr < region.end) or (
                offset is not None and offset < region.end_offset
            ):
                break
        else:
            return
        # If starting region is placed after starting point
        if (addr is not None and addr < region.addr) or (
            offset is not None and offset < region.offset
        ):
            # If expect only contiguous regions: we can't return anything
            if contiguous:
                return
            # If not, we just need to adjust our starting point
            if addr is not None:
                if length is not None:
                    length -= region.addr - addr
                addr = region.addr
            else:
                if length is not None:
                    raise ValueError(
                        "Don't know how to retrieve length-limited regions with offset from unmapped area"
                    )
                offset = region.offset
            # If we're out of length after adjustment: time to stop
            if length is not None and length <= 0:
                return
        # Now, our starting "addr"/"offset" is placed inside starting "region"
        # Let's translate our offset to addr if necessary
        if addr is None:
            if offset is None:
                raise RuntimeError(
                    "Something went wrong, starting region offset is set to None?"
                )
            addr = region.p2v(offset)
        # Continue enumeration
        prev_region = None
        for region in self.regions[region_idx:]:
            intersection = region.trim_range(addr, length)
            # If we've got empty intersection: time to break
            if not intersection:
                break
            # Is it still contiguous to previous?
            if contiguous and prev_region and prev_region.end != region.addr:
                break
            yield intersection if trim else region
            prev_region = region

    def v2p(self, addr, length=None):
        """
        Virtual address to buffer (physical) offset translation

        .. versionchanged:: 3.0.0

            Added optional mapping length check

        :param addr: Virtual address
        :param length: Expected minimal length of mapping (optional)
        :return: Buffer offset or None if virtual address is not mapped
        """
        if addr is None:
            return None
        mapping_length = 0
        for region in self.iter_regions(
            addr=addr, length=length, contiguous=True, trim=True
        ):
            if length is None:
                return region.v2p(addr)
            mapping_length += region.size
            if mapping_length >= length:
                return region.v2p(addr)
        else:
            return None

    def p2v(self, off, length=None):
        """
        Buffer (physical) offset to virtual address translation

        .. versionchanged:: 3.0.0

            Added optional mapping length check

        :param off: Buffer offset
        :param length: Expected minimal length of mapping (optional)
        :return: Virtual address or None if offset is not mapped
        """
        if off is None:
            return None
        mapping_length = 0
        for region in self.iter_regions(
            offset=off, length=length, contiguous=True, trim=True
        ):
            if length is None:
                return region.p2v(off)
            mapping_length += region.size
            if mapping_length >= length:
                return region.p2v(off)
        else:
            return None

    def is_addr(self, addr):
        """
        Checks whether provided parameter is correct virtual address
        :param addr: Virtual address candidate
        :return: True if it is mapped by ProcessMemory object
        """
        return self.v2p(addr) is not None

    def addr_region(self, addr):
        """
        Returns :class:`Region` object mapping specified virtual address

        :param addr: Virtual address
        :rtype: :class:`Region`
        """
        return next(self.iter_regions(addr=addr, contiguous=True), None)

    def readp(self, offset, length=None):
        """
        Read a chunk of memory from the specified buffer offset.

        .. warning::

            Family of *p methods doesn't care about contiguity of regions.

            Use :py:meth:`p2v` and :py:meth:`readv` if you want to operate on contiguous regions only

        :param offset: Buffer offset
        :param length: Length of chunk (optional)
        :return: Chunk from specified location
        :rtype: bytes
        """
        if length is None:
            return bytes(self.m[offset:])
        else:
            return bytes(self.m[offset : offset + length])

    def readv_regions(self, addr=None, length=None, contiguous=True):
        """
        Generate chunks of memory from next contiguous regions, starting from the specified virtual address,
        until specified length of read data is reached.

        Used internally.

        .. versionchanged:: 3.0.0

            Contents of contiguous regions are merged into single string

        :param addr: Virtual address
        :param length: Size of memory to read (optional)
        :param contiguous: If True, readv_regions breaks after first gap
        :rtype: Iterator[Tuple[int, bytes]]
        """
        current_addr = 0
        current_strings: List[bytes] = []
        prev_region = None
        for region in self.iter_regions(
            addr=addr, length=length, contiguous=contiguous, trim=True
        ):
            if not prev_region or prev_region.end != region.addr:
                if current_strings:
                    yield current_addr, b"".join(current_strings)
                current_addr = region.addr
                current_strings = []
            current_strings.append(self.readp(region.offset, region.size))
            prev_region = region
        if current_strings:
            yield current_addr, b"".join(current_strings)

    def readv(self, addr, length=None):
        """
        Read a chunk of memory from the specified virtual address

        :param addr: Virtual address
        :type addr: int
        :param length: Length of chunk (optional)
        :type length: int
        :return: Chunk from specified location
        :rtype: bytes
        """
        if length is not None and length <= 0:
            return b""
        _, chunk = next(self.readv_regions(addr, length), (0, b""))
        return chunk

    def readv_until(self, addr, s):
        """
        Read a chunk of memory until the stop marker

        :param addr: Virtual address
        :type addr: int
        :param s: Stop marker
        :type s: bytes
        :rtype: bytes
        """
        # readv_regions is merging contiguous regions now
        _, chunk = next(self.readv_regions(addr), (0, b""))
        idx = chunk.find(s)
        return chunk[:idx] if idx >= 0 else chunk

    def patchp(self, offset, buf):
        """
        Patch bytes under specified offset

        .. warning::

           Family of *p methods doesn't care about contiguity of regions.

           Use :py:meth:`p2v` and :py:meth:`patchv` if you want to operate on contiguous regions only

        :param offset: Buffer offset
        :type offset: int
        :param buf: Buffer with patch to apply
        :type buf: bytes

        Usage example:

        .. code-block:: python

            from malduck import procmempe, aplib

            with procmempe("mal1.exe.dmp") as ppe:
                # Decompress payload
                payload = aPLib().decompress(
                    ppe.readv(ppe.imgbase + 0x8400, ppe.imgend)
                )
                embed_pe = procmem(payload, base=0)
                # Fix headers
                embed_pe.patchp(0, b"MZ")
                embed_pe.patchp(embed_pe.uint32p(0x3C), b"PE")
                # Load patched image into procmempe
                embed_pe = procmempe.from_memory(embed_pe, image=True)
                assert embed_pe.asciiz(0x1000a410) == b"StrToIntExA"
        """
        self.m[offset : offset + len(buf)] = buf

    def patchv(self, addr, buf):
        """
        Patch bytes under specified virtual address

        Patched address range must be within single region, ValueError is raised otherwise.

        :param addr: Virtual address
        :type addr: int
        :param buf: Buffer with patch to apply
        :type buf: bytes
        """
        region = self.addr_region(addr)
        # Boundary check
        if region is None or region.end < (addr + len(buf)):
            raise ValueError(
                "Patched bytes range must be contained within single, existing region"
            )
        return self.patchp(region.v2p(addr), buf)

    def uint8p(self, offset, fixed=False):
        """Read unsigned 8-bit value at offset."""
        return uint8(self.readp(offset, 1), fixed=fixed)

    def uint16p(self, offset, fixed=False):
        """Read unsigned 16-bit value at offset."""
        return uint16(self.readp(offset, 2), fixed=fixed)

    def uint32p(self, offset, fixed=False):
        """Read unsigned 32-bit value at offset."""
        return uint32(self.readp(offset, 4), fixed=fixed)

    def uint64p(self, offset, fixed=False):
        """Read unsigned 64-bit value at offset."""
        return uint64(self.readp(offset, 8), fixed=fixed)

    def uint8v(self, addr, fixed=False):
        """Read unsigned 8-bit value at address."""
        return uint8(self.readv(addr, 1), fixed=fixed)

    def uint16v(self, addr, fixed=False):
        """Read unsigned 16-bit value at address."""
        return uint16(self.readv(addr, 2), fixed=fixed)

    def uint32v(self, addr, fixed=False):
        """Read unsigned 32-bit value at address."""
        return uint32(self.readv(addr, 4), fixed=fixed)

    def uint64v(self, addr, fixed=False):
        """Read unsigned 64-bit value at address."""
        return uint64(self.readv(addr, 8), fixed=fixed)

    def int8p(self, offset, fixed=False):
        """Read signed 8-bit value at offset."""
        return int8(self.readp(offset, 1), fixed=fixed)

    def int16p(self, offset, fixed=False):
        """Read signed 16-bit value at offset."""
        return int16(self.readp(offset, 2), fixed=fixed)

    def int32p(self, offset, fixed=False):
        """Read signed 32-bit value at offset."""
        return int32(self.readp(offset, 4), fixed=fixed)

    def int64p(self, offset, fixed=False):
        """Read signed 64-bit value at offset."""
        return int64(self.readp(offset, 8), fixed=fixed)

    def int8v(self, addr, fixed=False):
        """Read signed 8-bit value at address."""
        return int8(self.readv(addr, 1), fixed=fixed)

    def int16v(self, addr, fixed=False):
        """Read signed 16-bit value at address."""
        return int16(self.readv(addr, 2), fixed=fixed)

    def int32v(self, addr, fixed=False):
        """Read signed 32-bit value at address."""
        return int32(self.readv(addr, 4), fixed=fixed)

    def int64v(self, addr, fixed=False):
        """Read signed 64-bit value at address."""
        return int64(self.readv(addr, 8), fixed=fixed)

    def asciiz(self, addr):
        """Read a null-terminated ASCII string at address."""
        return self.readv_until(addr, b"\x00")

    def utf16z(self, addr):
        """
        Read a null-terminated UTF-16 ASCII string at address.

        :param addr: Virtual address of string
        :rtype: bytes
        """
        buf = self.readv_until(addr, b"\x00\x00")
        """
        Can't use \x00\x00\x00 here because string can be just empty
        We just need to read one more byte in case string length is not even
        """
        if len(buf) % 2:
            buf += self.readv(addr + len(buf), 1)
        return utf16z(buf + b"\x00\x00")

    def _find(self, buf, query, offset=None, length=None):
        offset = offset or 0
        while True:
            if length is None:
                idx = buf.find(query, offset)
            else:
                idx = buf.find(query, offset, offset + length)
            if idx < 0:
                break
            yield idx
            offset = idx + 1

    def findp(self, query, offset=None, length=None):
        """
        Find raw bytes in memory (non-region-wise).

        If offset is None, looks for substring from the beginning of memory

        :param query: Substring to find
        :type query: bytes
        :param offset: Offset in buffer where searching starts
        :type offset: int (optional)
        :param length: Length of searched area
        :type length: int (optional)
        :return: Generates offsets where bytes were found
        :rtype: Iterator[int]
        """
        return self._find(self.m, query, offset, length)

    def findv(self, query, addr=None, length=None):
        """
        Find raw bytes in memory (region-wise)

        If addr is None, looks for substring from the beginning of memory

        :param query: Substring to find
        :type query: bytes
        :param addr: Virtual address of region where searching starts
        :type addr: int (optional)
        :param length: Length of searched area
        :type length: int (optional)
        :return: Generates offsets where regex was matched
        :rtype: Iterator[int]
        """
        for chunk_addr, chunk in self.readv_regions(addr, length, contiguous=False):
            for idx in self._find(chunk, query):
                yield idx + chunk_addr

    def regexp(self, query, offset=None, length=None):
        """
        Performs regex on the memory contents (non-region-wise)

        If offset is None, looks for match from the beginning of memory

        :param query: Regular expression to find
        :type query: bytes
        :param offset: Offset in buffer where searching starts
        :type offset: int (optional)
        :param length: Length of searched area
        :type length: int (optional)
        :return: Generates offsets where regex was matched
        :rtype: Iterator[int]
        """
        offset = offset or 0
        chunk = self.readp(offset, length)
        if not isinstance(query, bytes):
            # Can't just encode the string.
            # E.g. '\xf7'.encode('utf-8') would be encoded to b'\xc3\xb7'
            # instead of b'\xf7'.
            raise TypeError("Query argument must be binary type (bytes)")
        for entry in re.finditer(query, chunk, re.DOTALL):
            yield offset + entry.start()

    def regexv(self, query, addr=None, length=None):
        """
        Performs regex on the memory contents (region-wise)

        If addr is None, looks for match from the beginning of memory

        :param query: Regular expression to find
        :type query: bytes
        :param addr: Virtual address of region where searching starts
        :type addr: int (optional)
        :param length: Length of searched area
        :type length: int (optional)
        :return: Generates offsets where regex was matched
        :rtype: Iterator[int]

        .. warning::

           Method doesn't match bytes overlapping the border between regions
        """
        if not isinstance(query, bytes):
            # Can't just encode the string.
            # E.g. '\xf7'.encode('utf-8') would be encoded to b'\xc3\xb7'
            # instead of b'\xf7'.
            raise TypeError("Query argument must be binary type (bytes)")
        for chunk_addr, chunk in self.readv_regions(addr, length, contiguous=False):
            for entry in re.finditer(query, chunk, re.DOTALL):
                yield chunk_addr + entry.start()

    def disasmv(self, addr, size=None, x64=False, count=None):
        """
        Disassembles code under specified address

        .. versionchanged:: 4.0.0
            Returns iterator instead of list of instructions

        :param addr: Virtual address
        :type addr: int
        :param size: Size of disassembled buffer
        :type size: int (optional)
        :param count: Number of instructions to disassemble
        :type count: int (optional)
        :param x64: Assembly is 64bit
        :type x64: bool (optional)
        :return: :class:`List[Instruction]`
        """
        if (not size and not count) or (size and count):
            raise ValueError("procmem.disasmv needs either size or count to be set")
        if count:
            # Get the the maximum possible code size assuming maximum instruction size
            size = count * 15
        return disasm(data=self.readv(addr, size), addr=addr, x64=x64, count=count or 0)

    def extract(self, modules=None, extract_manager=None):
        """
        Tries to extract config from ProcessMemory object

        :param modules: Extractor modules object (optional, loads '~/.malduck' by default)
        :type modules: :class:`malduck.extractor.ExtractorModules`
        :param extract_manager: ExtractManager object (optional, creates ExtractManager by default)
        :type extract_manager: :class:`malduck.extractor.ExtractManager`
        :return: Static configuration(s) (:py:attr:`malduck.extractor.ExtractManager.config`) or None if not extracted
        :rtype: List[dict] or None
        """
        from ..extractor import ExtractManager, ExtractorModules

        if extract_manager is None:
            if modules is None:
                modules = ExtractorModules()
            extract_manager = ExtractManager(modules)
        extract_manager.push_procmem(self)
        return extract_manager.config

    def yarap(self, ruleset, offset=None, length=None, extended=False):
        """
        Perform yara matching (non-region-wise)

        If offset is None, looks for match from the beginning of memory

        .. versionchanged:: 4.0.0

            Added `extended` option which allows to get extended information about matched strings and rules.
            Default is False for backwards compatibility.

        :param ruleset: Yara object with loaded yara rules
        :type ruleset: :class:`malduck.yara.Yara`
        :param offset: Offset in buffer where searching starts
        :type offset: int (optional)
        :param length: Length of searched area
        :type length: int (optional)
        :param extended: Returns extended information about matched strings and rules
        :type extended: bool (optional, default False)
        :rtype: :class:`malduck.yara.YaraMatches`
        """
        return ruleset.match(extended=extended, data=self.readp(offset or 0, length))

    def yarav(self, ruleset, addr=None, length=None, extended=False):
        """
        Perform yara matching (region-wise)

        If addr is None, looks for match from the beginning of memory

        .. versionchanged:: 4.0.0

            Added `extended` option which allows to get extended information about matched strings and rules.
            Default is False for backwards compatibility.

        :param ruleset: Yara object with loaded yara rules
        :type ruleset: :class:`malduck.yara.Yara`
        :param addr: Virtual address of region where searching starts
        :type addr: int (optional)
        :param length: Length of searched area
        :type length: int (optional)
        :param extended: Returns extended information about matched strings and rules
        :type extended: bool (optional, default False)
        :rtype: :class:`malduck.yara.YaraRulesetOffsets` or :class:`malduck.yara.YaraRulesetMatches`
                if extended is set to True
        """
        if addr is None:
            addr = self.regions[0].addr
        if length is None:
            length = self.regions[-1].end - addr

        def map_offset(off, len):
            ptr = self.p2v(off, len)
            if ptr is not None and addr <= ptr < addr + length:
                return ptr

        return ruleset.match(
            offset_mapper=map_offset, extended=extended, data=self.readp(0)
        )

    def _findbytes(self, yara_fn, query, addr, length):
        if isinstance(query, bytes):
            query = query.decode()

        rule = Yara(strings=YaraString(query, type=YaraString.HEX))
        match = yara_fn(rule, addr, length, extended=True)
        if match:
            for string_match in match.r.string:
                yield string_match.offset

    def findbytesp(self, query, offset=None, length=None):
        """
        Search for byte sequences (e.g., `4? AA BB ?? DD`). Uses :py:meth:`yarap` internally

        If offset is None, looks for match from the beginning of memory

        .. versionadded:: 1.4.0
           Query is passed to yarap as single hexadecimal string rule. Use Yara-compatible strings only

        :param query: Sequence of wildcarded hexadecimal bytes, separated by spaces
        :type query: str or bytes
        :param offset: Buffer offset where searching will be started
        :type offset: int (optional)
        :param length: Length of searched area
        :type length: int (optional)
        :return: Iterator returning next offsets
        :rtype: Iterator[int]
        """
        return self._findbytes(self.yarap, query, offset, length)

    def findbytesv(self, query, addr=None, length=None):
        """
        Search for byte sequences (e.g., `4? AA BB ?? DD`). Uses :py:meth:`yarav` internally

        If addr is None, looks for match from the beginning of memory

        .. versionadded:: 1.4.0
           Query is passed to yarav as single hexadecimal string rule. Use Yara-compatible strings only

        :param query: Sequence of wildcarded hexadecimal bytes, separated by spaces
        :type query: str or bytes
        :param addr: Virtual address where searching will be started
        :type addr: int (optional)
        :param length: Length of searched area
        :type length: int (optional)
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
        return self._findbytes(self.yarav, query, addr, length)

    def findmz(self, addr):
        """
        Tries to locate MZ header based on address inside PE image

        :param addr: Virtual address inside image
        :type addr: int
        :return: Virtual address of found MZ header or None
        """
        addr &= ~0xFFF
        while True:
            buf = self.readv(addr, 2)
            if not buf:
                return None
            if buf == b"MZ":
                return addr
            addr -= 0x1000


procmem = ProcessMemory

import mmap
from collections.abc import Iterator
from typing import Any, BinaryIO, TypeVar, overload

from typing_extensions import Literal, Protocol, TypeAlias

from ..disasm import Instruction
from ..extractor import ExtractManager, ExtractorModules
from ..ints import IntType
from ..yara import Yara, YaraRulesetMatch, YaraRulesetOffsets
from .region import Region

class MemoryBuffer:
    def __setitem__(self, item: int | slice, value: int | slice): ...
    def __getitem__(self, item: int | slice): ...
    def __len__(self) -> int: ...

ProcessMemoryBuffer: TypeAlias = bytes | bytearray | mmap.mmap | MemoryBuffer
T = TypeVar("T", bound="ProcessMemory")

procmem: type[ProcessMemory]

class ProcessMemoryYaraCallback(Protocol):
    @overload
    def __call__(
        self,
        ruleset: Yara,
        addr: int | None,
        length: int | None,
        extended: Literal[True],
    ) -> YaraRulesetMatch: ...
    @overload
    def __call__(
        self,
        ruleset: Yara,
        offset: int | None,
        length: int | None,
        extended: Literal[True],
    ) -> YaraRulesetMatch: ...

class ProcessMemory:
    f: BinaryIO | None
    memory: bytearray | None
    mapped_memory: mmap.mmap | None
    imgbase: int
    regions: list[Region]
    def __init__(
        self,
        buf: ProcessMemoryBuffer,
        base: int = 0,
        regions: list[Region] | None = None,
        **_,
    ) -> None: ...
    def __enter__(self): ...
    def __exit__(self, exc_type, exc_val, exc_tb): ...
    @property
    def m(self) -> bytearray: ...
    def close(self, copy: bool = False) -> None: ...
    @classmethod
    def from_file(cls: type[T], filename: str, **kwargs) -> T: ...
    @classmethod
    def from_memory(
        cls: type[T],
        memory: ProcessMemory,
        base: int = None,
        **kwargs,
    ) -> T: ...
    @property
    def length(self) -> int: ...
    def iter_regions(
        self,
        addr: int | None = None,
        offset: int | None = None,
        length: int | None = None,
        contiguous: bool = False,
        trim: bool = False,
    ) -> Iterator[Region]: ...
    def v2p(self, addr: int | None, length: int | None = None) -> int | None: ...
    def p2v(self, off: int | None, length: int | None = None) -> int | None: ...
    def is_addr(self, addr: int | None) -> bool: ...
    def addr_region(self, addr: int | None) -> Region | None: ...
    def readp(self, offset: int, length: int | None = None) -> bytes: ...
    def readv_regions(
        self,
        addr: int | None = None,
        length: int | None = None,
        contiguous: bool = True,
    ) -> Iterator[tuple[int, bytes]]: ...
    def readv(self, addr: int, length: int | None = None) -> bytes: ...
    def readv_until(self, addr: int, s: bytes) -> bytes: ...
    def patchp(self, offset: int, buf: bytes) -> None: ...
    def patchv(self, addr: int, buf: bytes) -> None: ...
    @overload
    def uint8p(self, offset: int, fixed: Literal[False]) -> int | None: ...
    @overload
    def uint8p(self, offset: int, fixed: Literal[True]) -> IntType | None: ...
    @overload
    def uint8p(self, offset: int) -> int | None: ...
    @overload
    def uint16p(self, offset: int, fixed: Literal[False]) -> int | None: ...
    @overload
    def uint16p(self, offset: int, fixed: Literal[True]) -> IntType | None: ...
    @overload
    def uint16p(self, offset: int) -> int | None: ...
    @overload
    def uint32p(self, offset: int, fixed: Literal[False]) -> int | None: ...
    @overload
    def uint32p(self, offset: int, fixed: Literal[True]) -> IntType | None: ...
    @overload
    def uint32p(self, offset: int) -> int | None: ...
    @overload
    def uint64p(self, offset: int, fixed: Literal[False]) -> int | None: ...
    @overload
    def uint64p(self, offset: int, fixed: Literal[True]) -> IntType | None: ...
    @overload
    def uint64p(self, offset: int) -> int | None: ...
    @overload
    def uint8v(self, addr: int, fixed: Literal[False]) -> int | None: ...
    @overload
    def uint8v(self, addr: int, fixed: Literal[True]) -> IntType | None: ...
    @overload
    def uint8v(self, addr: int) -> int | None: ...
    @overload
    def uint16v(self, addr: int, fixed: Literal[False]) -> int | None: ...
    @overload
    def uint16v(self, addr: int, fixed: Literal[True]) -> IntType | None: ...
    @overload
    def uint16v(self, addr: int) -> int | None: ...
    @overload
    def uint32v(self, addr: int, fixed: Literal[False]) -> int | None: ...
    @overload
    def uint32v(self, addr: int, fixed: Literal[True]) -> IntType | None: ...
    @overload
    def uint32v(self, addr: int) -> int | None: ...
    @overload
    def uint64v(self, addr: int, fixed: Literal[False]) -> int | None: ...
    @overload
    def uint64v(self, addr: int, fixed: Literal[True]) -> IntType | None: ...
    @overload
    def uint64v(self, addr: int) -> int | None: ...
    @overload
    def int8p(self, offset: int, fixed: Literal[False]) -> int | None: ...
    @overload
    def int8p(self, offset: int, fixed: Literal[True]) -> IntType | None: ...
    @overload
    def int8p(self, offset: int) -> int | None: ...
    @overload
    def int16p(self, offset: int, fixed: Literal[False]) -> int | None: ...
    @overload
    def int16p(self, offset: int, fixed: Literal[True]) -> IntType | None: ...
    @overload
    def int16p(self, offset: int) -> int | None: ...
    @overload
    def int32p(self, offset: int, fixed: Literal[False]) -> int | None: ...
    @overload
    def int32p(self, offset: int, fixed: Literal[True]) -> IntType | None: ...
    @overload
    def int32p(self, offset: int) -> int | None: ...
    @overload
    def int64p(self, offset: int, fixed: Literal[False]) -> int | None: ...
    @overload
    def int64p(self, offset: int, fixed: Literal[True]) -> IntType | None: ...
    @overload
    def int64p(self, offset: int) -> int | None: ...
    @overload
    def int8v(self, addr: int, fixed: Literal[False]) -> int | None: ...
    @overload
    def int8v(self, addr: int, fixed: Literal[True]) -> IntType | None: ...
    @overload
    def int8v(self, addr: int) -> int | None: ...
    @overload
    def int16v(self, addr: int, fixed: Literal[False]) -> int | None: ...
    @overload
    def int16v(self, addr: int, fixed: Literal[True]) -> IntType | None: ...
    @overload
    def int16v(self, addr: int) -> int | None: ...
    @overload
    def int32v(self, addr: int, fixed: Literal[False]) -> int | None: ...
    @overload
    def int32v(self, addr: int, fixed: Literal[True]) -> IntType | None: ...
    @overload
    def int32v(self, addr: int) -> int | None: ...
    @overload
    def int64v(self, addr: int, fixed: Literal[False]) -> int | None: ...
    @overload
    def int64v(self, addr: int, fixed: Literal[True]) -> IntType | None: ...
    @overload
    def int64v(self, addr: int) -> int | None: ...
    def asciiz(self, addr: int) -> bytes: ...
    def utf16z(self, addr: int) -> bytes: ...
    def _find(
        self,
        buf: bytes,
        query: bytes,
        offset: int | None = None,
        length: int | None = None,
    ) -> Iterator[int]: ...
    def findp(
        self,
        query: bytes,
        offset: int | None = None,
        length: int | None = None,
    ) -> Iterator[int]: ...
    def findv(
        self,
        query: bytes,
        addr: int | None = None,
        length: int | None = None,
    ) -> Iterator[int]: ...
    def regexp(
        self,
        query: bytes,
        offset: int | None = None,
        length: int | None = None,
    ) -> Iterator[int]: ...
    def regexv(
        self,
        query: bytes,
        addr: int | None = None,
        length: int | None = None,
    ) -> Iterator[int]: ...
    def disasmv(
        self,
        addr: int,
        size: int | None = None,
        x64: bool = False,
        count: int | None = None,
    ) -> Iterator[Instruction]: ...
    def extract(
        self,
        modules: ExtractorModules = None,
        extract_manager: ExtractManager = None,
    ) -> list[dict[str, Any]] | None: ...
    # yarap(ruleset)
    # yarap(ruleset, offset)
    # yarap(ruleset, offset, length)
    # yarap(ruleset, offset, length, extended=False)
    @overload
    def yarap(
        self,
        ruleset: Yara,
        offset: int | None = None,
        length: int | None = None,
        extended: Literal[False] = False,
    ) -> YaraRulesetOffsets: ...
    # yarap(ruleset, offset, length, extended=True)
    @overload
    def yarap(
        self,
        ruleset: Yara,
        offset: int | None,
        length: int | None,
        extended: Literal[True],
    ) -> YaraRulesetMatch: ...
    # yarap(ruleset, extended=True)
    @overload
    def yarap(self, ruleset: Yara, *, extended: Literal[True]) -> YaraRulesetMatch: ...
    # yarap(ruleset, offset=0, extended=True)
    # yarap(ruleset, 0, extended=True)
    @overload
    def yarap(
        self,
        ruleset: Yara,
        offset: int | None,
        *,
        extended: Literal[True],
    ) -> YaraRulesetMatch: ...
    # yarap(ruleset, length=0, extended=True)
    @overload
    def yarap(
        self,
        ruleset: Yara,
        *,
        length: int | None,
        extended: Literal[True],
    ) -> YaraRulesetMatch: ...
    # yarav(ruleset)
    # yarav(ruleset, addr)
    # yarav(ruleset, addr, length)
    # yarav(ruleset, addr, length, extended=False)
    @overload
    def yarav(
        self,
        ruleset: Yara,
        addr: int | None = None,
        length: int | None = None,
        extended: Literal[False] = False,
    ) -> YaraRulesetOffsets: ...
    # yarav(ruleset, addr, length, extended=True)
    @overload
    def yarav(
        self,
        ruleset: Yara,
        addr: int | None,
        length: int | None,
        extended: Literal[True],
    ) -> YaraRulesetMatch: ...
    # yarav(ruleset, extended=True)
    @overload
    def yarav(self, ruleset: Yara, *, extended: Literal[True]) -> YaraRulesetMatch: ...
    # yarav(ruleset, addr=0, extended=True)
    # yarav(ruleset, 0, extended=True)
    @overload
    def yarav(
        self,
        ruleset: Yara,
        addr: int | None,
        *,
        extended: Literal[True],
    ) -> YaraRulesetMatch: ...
    # yarav(ruleset, length=0, extended=True)
    @overload
    def yarav(
        self,
        ruleset: Yara,
        *,
        length: int | None,
        extended: Literal[True],
    ) -> YaraRulesetMatch: ...
    def _findbytes(
        self,
        yara_fn: ProcessMemoryYaraCallback,
        query: str | bytes,
        addr: int | None,
        length: int | None,
    ) -> Iterator[int]: ...
    def findbytesp(
        self,
        query: str | bytes,
        offset: int | None = None,
        length: int | None = None,
    ) -> Iterator[int]: ...
    def findbytesv(
        self,
        query: str | bytes,
        addr: int | None = None,
        length: int | None = None,
    ) -> Iterator[int]: ...
    def findmz(self, addr: int) -> int | None: ...

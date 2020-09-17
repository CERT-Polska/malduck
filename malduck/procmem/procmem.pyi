import mmap

from typing import (
    Any,
    BinaryIO,
    Dict,
    Iterator,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)

from typing_extensions import Literal, Protocol

from ..extractor import ExtractorModules, ExtractManager

from .region import Region
from ..disasm import Instruction
from ..yara import Yara, YaraRulesetMatch, YaraRulesetOffsets

from ..ints import IntType

class MemoryBuffer(object):
    def __setitem__(self, item: Union[int, slice], value: Union[int, slice]): ...
    def __getitem__(self, item: Union[int, slice]): ...
    def __len__(self) -> int: ...

ProcessMemoryBuffer = Union[bytes, bytearray, mmap.mmap, MemoryBuffer]
T = TypeVar("T", bound="ProcessMemory")

procmem: Type["ProcessMemory"]

class ProcessMemoryYaraCallback(Protocol):
    @overload
    def __call__(
        self,
        ruleset: Yara,
        addr: Optional[int],
        length: Optional[int],
        extended: Literal[True],
    ) -> YaraRulesetMatch: ...
    @overload
    def __call__(
        self,
        ruleset: Yara,
        offset: Optional[int],
        length: Optional[int],
        extended: Literal[True],
    ) -> YaraRulesetMatch: ...

class ProcessMemory:
    f: Optional[BinaryIO]
    memory: Optional[bytearray]
    mapped_memory: Optional[mmap.mmap]
    imgbase: int
    regions: List[Region]
    def __init__(
        self,
        buf: ProcessMemoryBuffer,
        base: int = 0,
        regions: Optional[List[Region]] = None,
        **_,
    ) -> None: ...
    def __enter__(self): ...
    def __exit__(self, exc_type, exc_val, exc_tb): ...
    @property
    def m(self) -> bytearray: ...
    def close(self, copy: bool = False) -> None: ...
    @classmethod
    def from_file(cls: Type[T], filename: str, **kwargs) -> T: ...
    @classmethod
    def from_memory(
        cls: Type[T], memory: "ProcessMemory", base: int = None, **kwargs
    ) -> T: ...
    @property
    def length(self) -> int: ...
    def iter_regions(
        self,
        addr: Optional[int] = None,
        offset: Optional[int] = None,
        length: Optional[int] = None,
        contiguous: bool = False,
        trim: bool = False,
    ) -> Iterator[Region]: ...
    def v2p(
        self, addr: Optional[int], length: Optional[int] = None
    ) -> Optional[int]: ...
    def p2v(
        self, off: Optional[int], length: Optional[int] = None
    ) -> Optional[int]: ...
    def is_addr(self, addr: Optional[int]) -> bool: ...
    def addr_region(self, addr: Optional[int]) -> Optional[Region]: ...
    def readp(self, offset: int, length: Optional[int] = None) -> bytes: ...
    def readv_regions(
        self,
        addr: Optional[int] = None,
        length: Optional[int] = None,
        contiguous: bool = True,
    ) -> Iterator[Tuple[int, bytes]]: ...
    def readv(self, addr: int, length: Optional[int] = None) -> bytes: ...
    def readv_until(self, addr: int, s: bytes) -> bytes: ...
    def patchp(self, offset: int, buf: bytes) -> None: ...
    def patchv(self, addr: int, buf: bytes) -> None: ...
    @overload
    def uint8p(self, offset: int, fixed: Literal[False]) -> Optional[int]: ...
    @overload
    def uint8p(self, offset: int, fixed: Literal[True]) -> Optional[IntType]: ...
    @overload
    def uint8p(self, offset: int) -> Optional[int]: ...
    @overload
    def uint16p(self, offset: int, fixed: Literal[False]) -> Optional[int]: ...
    @overload
    def uint16p(self, offset: int, fixed: Literal[True]) -> Optional[IntType]: ...
    @overload
    def uint16p(self, offset: int) -> Optional[int]: ...
    @overload
    def uint32p(self, offset: int, fixed: Literal[False]) -> Optional[int]: ...
    @overload
    def uint32p(self, offset: int, fixed: Literal[True]) -> Optional[IntType]: ...
    @overload
    def uint32p(self, offset: int) -> Optional[int]: ...
    @overload
    def uint64p(self, offset: int, fixed: Literal[False]) -> Optional[int]: ...
    @overload
    def uint64p(self, offset: int, fixed: Literal[True]) -> Optional[IntType]: ...
    @overload
    def uint64p(self, offset: int) -> Optional[int]: ...
    @overload
    def uint8v(self, addr: int, fixed: Literal[False]) -> Optional[int]: ...
    @overload
    def uint8v(self, addr: int, fixed: Literal[True]) -> Optional[IntType]: ...
    @overload
    def uint8v(self, addr: int) -> Optional[int]: ...
    @overload
    def uint16v(self, addr: int, fixed: Literal[False]) -> Optional[int]: ...
    @overload
    def uint16v(self, addr: int, fixed: Literal[True]) -> Optional[IntType]: ...
    @overload
    def uint16v(self, addr: int) -> Optional[int]: ...
    @overload
    def uint32v(self, addr: int, fixed: Literal[False]) -> Optional[int]: ...
    @overload
    def uint32v(self, addr: int, fixed: Literal[True]) -> Optional[IntType]: ...
    @overload
    def uint32v(self, addr: int) -> Optional[int]: ...
    @overload
    def uint64v(self, addr: int, fixed: Literal[False]) -> Optional[int]: ...
    @overload
    def uint64v(self, addr: int, fixed: Literal[True]) -> Optional[IntType]: ...
    @overload
    def uint64v(self, addr: int) -> Optional[int]: ...
    @overload
    def int8p(self, offset: int, fixed: Literal[False]) -> Optional[int]: ...
    @overload
    def int8p(self, offset: int, fixed: Literal[True]) -> Optional[IntType]: ...
    @overload
    def int8p(self, offset: int) -> Optional[int]: ...
    @overload
    def int16p(self, offset: int, fixed: Literal[False]) -> Optional[int]: ...
    @overload
    def int16p(self, offset: int, fixed: Literal[True]) -> Optional[IntType]: ...
    @overload
    def int16p(self, offset: int) -> Optional[int]: ...
    @overload
    def int32p(self, offset: int, fixed: Literal[False]) -> Optional[int]: ...
    @overload
    def int32p(self, offset: int, fixed: Literal[True]) -> Optional[IntType]: ...
    @overload
    def int32p(self, offset: int) -> Optional[int]: ...
    @overload
    def int64p(self, offset: int, fixed: Literal[False]) -> Optional[int]: ...
    @overload
    def int64p(self, offset: int, fixed: Literal[True]) -> Optional[IntType]: ...
    @overload
    def int64p(self, offset: int) -> Optional[int]: ...
    @overload
    def int8v(self, addr: int, fixed: Literal[False]) -> Optional[int]: ...
    @overload
    def int8v(self, addr: int, fixed: Literal[True]) -> Optional[IntType]: ...
    @overload
    def int8v(self, addr: int) -> Optional[int]: ...
    @overload
    def int16v(self, addr: int, fixed: Literal[False]) -> Optional[int]: ...
    @overload
    def int16v(self, addr: int, fixed: Literal[True]) -> Optional[IntType]: ...
    @overload
    def int16v(self, addr: int) -> Optional[int]: ...
    @overload
    def int32v(self, addr: int, fixed: Literal[False]) -> Optional[int]: ...
    @overload
    def int32v(self, addr: int, fixed: Literal[True]) -> Optional[IntType]: ...
    @overload
    def int32v(self, addr: int) -> Optional[int]: ...
    @overload
    def int64v(self, addr: int, fixed: Literal[False]) -> Optional[int]: ...
    @overload
    def int64v(self, addr: int, fixed: Literal[True]) -> Optional[IntType]: ...
    @overload
    def int64v(self, addr: int) -> Optional[int]: ...
    def asciiz(self, addr: int) -> bytes: ...
    def utf16z(self, addr: int) -> bytes: ...
    def _find(
        self,
        buf: bytes,
        query: bytes,
        offset: Optional[int] = None,
        length: Optional[int] = None,
    ) -> Iterator[int]: ...
    def findp(
        self, query: bytes, offset: Optional[int] = None, length: Optional[int] = None
    ) -> Iterator[int]: ...
    def findv(
        self, query: bytes, addr: Optional[int] = None, length: Optional[int] = None
    ) -> Iterator[int]: ...
    def regexp(
        self, query: bytes, offset: Optional[int] = None, length: Optional[int] = None
    ) -> Iterator[int]: ...
    def regexv(
        self, query: bytes, addr: Optional[int] = None, length: Optional[int] = None
    ) -> Iterator[int]: ...
    def disasmv(
        self,
        addr: int,
        size: Optional[int] = None,
        x64: bool = False,
        count: Optional[int] = None,
    ) -> Iterator[Instruction]: ...
    def extract(
        self, modules: ExtractorModules = None, extract_manager: ExtractManager = None,
    ) -> Optional[List[Dict[str, Any]]]: ...
    # yarap(ruleset)
    # yarap(ruleset, offset)
    # yarap(ruleset, offset, length)
    # yarap(ruleset, offset, length, extended=False)
    @overload
    def yarap(
        self,
        ruleset: Yara,
        offset: Optional[int] = None,
        length: Optional[int] = None,
        extended: Literal[False] = False,
    ) -> YaraRulesetOffsets: ...
    # yarap(ruleset, offset, length, extended=True)
    @overload
    def yarap(
        self,
        ruleset: Yara,
        offset: Optional[int],
        length: Optional[int],
        extended: Literal[True],
    ) -> YaraRulesetMatch: ...
    # yarap(ruleset, extended=True)
    @overload
    def yarap(self, ruleset: Yara, *, extended: Literal[True]) -> YaraRulesetMatch: ...
    # yarap(ruleset, offset=0, extended=True)
    # yarap(ruleset, 0, extended=True)
    @overload
    def yarap(
        self, ruleset: Yara, offset: Optional[int], *, extended: Literal[True]
    ) -> YaraRulesetMatch: ...
    # yarap(ruleset, length=0, extended=True)
    @overload
    def yarap(
        self, ruleset: Yara, *, length: Optional[int], extended: Literal[True]
    ) -> YaraRulesetMatch: ...
    # yarav(ruleset)
    # yarav(ruleset, addr)
    # yarav(ruleset, addr, length)
    # yarav(ruleset, addr, length, extended=False)
    @overload
    def yarav(
        self,
        ruleset: Yara,
        addr: Optional[int] = None,
        length: Optional[int] = None,
        extended: Literal[False] = False,
    ) -> YaraRulesetOffsets: ...
    # yarav(ruleset, addr, length, extended=True)
    @overload
    def yarav(
        self,
        ruleset: Yara,
        addr: Optional[int],
        length: Optional[int],
        extended: Literal[True],
    ) -> YaraRulesetMatch: ...
    # yarav(ruleset, extended=True)
    @overload
    def yarav(self, ruleset: Yara, *, extended: Literal[True]) -> YaraRulesetMatch: ...
    # yarav(ruleset, addr=0, extended=True)
    # yarav(ruleset, 0, extended=True)
    @overload
    def yarav(
        self, ruleset: Yara, addr: Optional[int], *, extended: Literal[True]
    ) -> YaraRulesetMatch: ...
    # yarav(ruleset, length=0, extended=True)
    @overload
    def yarav(
        self, ruleset: Yara, *, length: Optional[int], extended: Literal[True]
    ) -> YaraRulesetMatch: ...
    def _findbytes(
        self,
        yara_fn: ProcessMemoryYaraCallback,
        query: Union[str, bytes],
        addr: Optional[int],
        length: Optional[int],
    ) -> Iterator[int]: ...
    def findbytesp(
        self,
        query: Union[str, bytes],
        offset: Optional[int] = None,
        length: Optional[int] = None,
    ) -> Iterator[int]: ...
    def findbytesv(
        self,
        query: Union[str, bytes],
        addr: Optional[int] = None,
        length: Optional[int] = None,
    ) -> Iterator[int]: ...
    def findmz(self, addr: int) -> Optional[int]: ...

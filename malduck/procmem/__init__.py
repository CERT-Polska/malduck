from .procmem import ProcessMemory
from .procmempe import ProcessMemoryPE
from .procmemelf import ProcessMemoryELF
from .cuckoomem import CuckooProcessMemory
from .idamem import IDAProcessMemory

from .region import (
    Region,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY
)

procmem = ProcessMemory
procmempe = ProcessMemoryPE
procmemelf = ProcessMemoryELF
cuckoomem = CuckooProcessMemory
idamem = IDAProcessMemory

__all__ = [
    "ProcessMemory", "ProcessMemoryPE", "ProcessMemoryELF",
    "CuckooProcessMemory", "IDAProcessMemory",
    "Region", "PAGE_READONLY", "PAGE_READWRITE", "PAGE_WRITECOPY", "PAGE_EXECUTE",
    "PAGE_EXECUTE_READ", "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY",
    "procmem", "procmempe", "procmemelf", "cuckoomem", "idamem"
]

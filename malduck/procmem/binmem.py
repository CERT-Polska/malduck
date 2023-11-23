from __future__ import annotations

import logging
from abc import ABCMeta, abstractmethod
from typing import TYPE_CHECKING, TypeVar

from .procmem import ProcessMemory, ProcessMemoryBuffer

if TYPE_CHECKING:
    from .region import Region
    from collections.abc import Iterator

log = logging.getLogger(__name__)

T = TypeVar("T", bound="ProcessMemoryBinary")


class ProcessMemoryBinary(ProcessMemory, metaclass=ABCMeta):
    """
    Abstract class for memory-mapped executable binary
    """

    __magic__: bytes | None = None

    def __init__(
        self: T,
        buf: ProcessMemoryBuffer,
        base: int = 0,
        regions: list[Region] | None = None,
        image: bool = False,
        detect_image: bool = False,
    ) -> None:
        super().__init__(buf, base=base, regions=regions)
        if detect_image:
            image = self.is_image_loaded_as_memdump()
        self.is_image = image
        self._image: T | None = None
        if image:
            self._reload_as_image()

    @abstractmethod
    def _reload_as_image(self) -> None:
        """
        Load executable file embedded in ProcessMemory like native loader does
        """
        raise NotImplementedError

    @property
    def image(self: T) -> T | None:
        """
        Returns ProcessMemory object loaded with image=True or None
        if can't be loaded or is loaded as image yet
        """
        if self.is_image:
            return None
        try:
            if not self._image:
                self._image = type(self).from_memory(self, image=True)
            return self._image
        except Exception:
            import traceback

            log.debug(
                "image construction raised an exception: %s",
                traceback.format_exc(),
            )
            return None

    @abstractmethod
    def is_valid(self) -> bool:
        """
        Checks whether imgbase is pointing at valid binary header
        """
        raise NotImplementedError

    @classmethod
    def load_binaries_from_memory(cls: type[T], procmem: ProcessMemory) -> Iterator[T]:
        """
        Looks for binaries in ProcessMemory object and yields specialized
        ProcessMemoryBinary objects
        :param procmem: ProcessMemory object to search

        .. versionchanged:: 4.4.0

            In addition to image=False binaries, it also returns image=True versions.
            In previous versions it was done by extractor, so it was working only
            if memory-aligned version was also "valid".
        """
        if cls.__magic__ is None:
            raise NotImplementedError
        for binary_va in procmem.findv(cls.__magic__):
            binary_procmem_dmp = cls.from_memory(procmem, base=binary_va)
            if binary_procmem_dmp.is_valid():
                yield binary_procmem_dmp
            binary_procmem_img = binary_procmem_dmp.image
            if binary_procmem_img and binary_procmem_img.is_valid():
                yield binary_procmem_img

    @abstractmethod
    def is_image_loaded_as_memdump(self) -> bool:
        """
        Uses some heuristics to deduce whether contents can be loaded with `image=True`.
        Used by `detect_image`
        """
        raise NotImplementedError

    def __repr__(self):
        return ":".join(
            (
                type(self).__name__,
                "IMG" if self.is_image else "DMP",
                f"{self.imgbase:x}",
            )
        )

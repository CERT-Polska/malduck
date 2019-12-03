from .procmem import ProcessMemory


class ProcessMemoryBinary(ProcessMemory):
    """
    Abstract class for memory-mapped executable binary
    """
    __magic__ = None

    def __init__(self, buf, base=0, regions=None, image=False, detect_image=False):
        super(ProcessMemoryBinary, self).__init__(buf, base=base, regions=regions)
        if detect_image:
            image = self.is_image_loaded_as_memdump()
        self.is_image = image
        self._image = None
        if image:
            self._reload_as_image()

    def _reload_as_image(self):
        """
        Load executable file embedded in ProcessMemory like native loader does
        """
        raise NotImplementedError()

    @property
    def image(self):
        """
        Returns ProcessMemory object loaded with image=True or None if can't be loaded or is loaded as image yet
        """
        if self.is_image:
            return None
        try:
            if not self._image:
                self._image = self.__class__.from_memory(self, image=True)
            return self._image
        except Exception:
            return None

    def is_valid(self):
        """
        Checks whether imgbase is pointing at valid binary header
        """
        raise NotImplementedError()

    @classmethod
    def load_binaries_from_memory(cls, procmem):
        """
        Looks for binaries in ProcessMemory object and yields specialized ProcessMemoryBinary objects
        :param procmem: ProcessMemory object to search
        """
        if cls.__magic__ is None:
            raise NotImplementedError()
        for binary_va in procmem.findv(cls.__magic__):
            binary_procmem = cls.from_memory(procmem, base=binary_va)
            if binary_procmem.is_valid():
                yield binary_procmem

    def is_image_loaded_as_memdump(self):
        """
        Uses some heuristics to deduce whether contents can be loaded with `image=True`.
        Used by `detect_image`
        """
        raise NotImplementedError()

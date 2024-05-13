import mmap
from abc import ABC, abstractmethod
from typing import Optional, Union


class MemoryBuffer(ABC):
    @abstractmethod
    def __getitem__(self, item: slice) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def __setitem__(self, item: slice, value: bytes) -> None:
        raise NotImplementedError

    @abstractmethod
    def __len__(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def slice(
        self, from_offset: Optional[int] = None, to_offset: Optional[int] = None
    ) -> "MemoryBuffer":
        raise NotImplementedError

    @abstractmethod
    def release(self) -> None:
        raise NotImplementedError


class PlainMemoryBuffer(MemoryBuffer):
    def __init__(
        self,
        buf: Union[bytes, bytearray, memoryview],
    ) -> None:
        print("created ", self, id(self))
        if type(buf) is memoryview:
            self.buf = buf
        elif type(buf) in (bytearray, bytes):
            self.buf = memoryview(buf)
        else:
            raise TypeError(
                "Buffer in PlainMemoryBuffer must be memoryview, bytes or bytearray"
            )

    def __getitem__(self, item: slice) -> bytes:
        return bytes(self.buf[item])

    def __setitem__(self, item: slice, value: bytes) -> None:
        if self.buf.readonly:
            # If buffer is read-only, make a copy (on write)
            patchable_buf = memoryview(bytearray(self.buf))
            self.buf.release()
            self.buf = patchable_buf
        self.buf[item] = value

    def __len__(self) -> int:
        return len(self.buf)

    def slice(
        self, from_offset: Optional[int] = None, to_offset: Optional[int] = None
    ) -> "MemoryBuffer":
        """
        Creates a derived MemoryBuffer object representing slice of an underlying memory.

        Derived buffer is readonly, so __setitem__ will first make a copy before applying
        changes. It means that changes on parent buffer may be seen in derived buffers,
        but not the other way.
        """
        return PlainMemoryBuffer(self.buf[from_offset:to_offset].toreadonly())

    def release(self) -> None:
        print("released ", self, id(self))
        self.buf.release()


class MmapMemoryBuffer(PlainMemoryBuffer):
    def __init__(
        self,
        file_name: Optional[str] = None,
        mapped_buf: Optional[mmap.mmap] = None,
    ):
        self.opened_file = None
        self.mapped_buf = mapped_buf
        if mapped_buf is None and file_name is None:
            raise ValueError("Either file_name or map is required.")
        if file_name is not None:
            self.opened_file = open(file_name, "rb")
            try:
                # Allow copy-on-write
                if hasattr(mmap, "ACCESS_COPY"):
                    self.mapped_buf = mmap.mmap(
                        self.opened_file.fileno(), 0, access=mmap.ACCESS_COPY
                    )
                else:
                    raise RuntimeError("mmap with CoW is not supported on your OS")
                super().__init__(memoryview(self.mapped_buf))
            except RuntimeError:
                # Fallback to file.read()
                super().__init__(memoryview(self.opened_file.read()))
                self.opened_file.close()
                self.opened_file = None

    def release(self) -> None:
        super().release()
        if self.mapped_buf is not None:
            self.mapped_buf.close()
            self.mapped_buf = None
        if self.opened_file is not None:
            self.opened_file.close()
            self.opened_file = None

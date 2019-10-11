# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

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
    """Represents single mapped region in :class:`ProcessMemory`"""

    def __init__(self, addr, size, state, type_, protect, offset):
        self.addr = addr
        self.size = size
        self.state = state
        self.type_ = type_
        self.protect = protect
        self.offset = offset

    def to_json(self):
        """
        Returns JSON-like dict representation
        """
        return {
            "addr": "0x%08x" % self.addr,
            "end": "0x%08x" % (self.addr + self.size),
            "size": self.size,
            "state": self.state,
            "type": self.type_,
            "protect": page_access.get(self.protect),
            "offset": self.offset,
        }

    @property
    def end(self):
        """
        Virtual address of region end (first unmapped byte)
        """
        return self.addr + self.size

    @property
    def end_offset(self):
        """
        Offset of region end (first unmapped byte)
        """
        return self.offset + self.size

    @property
    def last(self):
        """
        Virtual address of last region byte
        """
        return self.addr + self.size - 1

    @property
    def last_offset(self):
        """
        Offset of last region byte
        """
        return self.offset + self.size - 1

    def v2p(self, addr):
        """
        Virtual address to physical offset translation. Assumes that address is valid within Region.
        :param addr: Virtual address
        :return: Physical offset
        """
        return self.offset + addr - self.addr

    def p2v(self, off):
        """
        Physical offset to translation. Assumes that offset is valid within Region.
        :param addr: Physical offset
        :return: Virtual address
        """
        return self.addr + off - self.offset

    def contains_offset(self, offset):
        """
        Checks whether region contains provided physical offset
        """
        return self.offset <= offset < self.offset + self.size

    def contains_addr(self, addr):
        """
        Checks whether region contains provided virtual address
        """
        return self.addr <= addr < self.end

    def intersects_range(self, addr, length):
        """
        Checks whether region mapping intersects with provided range
        """
        return self.addr < addr + length and addr < self.end

    def trim_range(self, addr, length=None):
        """
        Returns region intersection with provided range
        :param addr: Virtual address of starting point
        :param length: Length of range (optional)
        :rtype: :class:`Region`
        """
        new_addr = max(self.addr, addr)
        new_end = min(self.end, addr + length) if length is not None else self.end
        if new_end <= new_addr:
            return None
        new_offset = self.v2p(new_addr)
        return Region(new_addr, new_end - new_addr, self.state, self.type_, self.protect, new_offset)

    def __eq__(self, other):
        if not isinstance(other, Region):
            raise ValueError("Not a region object!")

        return (
            self.addr == other.addr and self.size == other.size and
            self.state == other.state and self.type_ == other.type_ and
            self.protect == other.protect and self.offset == other.offset
        )

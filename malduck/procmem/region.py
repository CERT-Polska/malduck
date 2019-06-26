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

    def __eq__(self, other):
        if not isinstance(other, Region):
            raise ValueError("Not a region object!")

        return (
            self.addr == other.addr and self.size == other.size and
            self.state == other.state and self.type_ == other.type_ and
            self.protect == other.protect
        )

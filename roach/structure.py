# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import ctypes

from roach.string.bin import (
    int8, uint8, int16, uint16, int32, uint32, int64, uint64
)

mapping = {
    int8: ctypes.c_byte,
    uint8: ctypes.c_ubyte,
    int16: ctypes.c_short,
    uint16: ctypes.c_ushort,
    int32: ctypes.c_int,
    uint32: ctypes.c_uint,
    int64: ctypes.c_longlong,
    uint64: ctypes.c_ulonglong,
}

class Structure(object):
    # TODO Default value in Python, should we change this to 1?
    _pack_ = 0
    _fields_ = []

    def __init__(self):
        self.subfields, fields = {}, []
        for field, type_ in self._fields_:
            if type_ in mapping:
                type_ = mapping[type_]
            elif issubclass(type_, Structure):
                # Keep track, likely for Python GC purposes.
                self.subfields[field] = type_()
                type_ = self.subfields[field].klass
            fields.append((field, type_))

        class klass(ctypes.Structure):
            _pack_ = self._pack_
            _fields_ = fields

            def as_dict(self):
                return self._parent_.as_dict()

        self.klass = klass
        self.klass._parent_ = self

    def __getattr__(self, item):
        return getattr(self.values, item)

    def as_dict(self, values=None):
        ret = {}
        for field, type_ in self._fields_:
            value = getattr(values or self.values, field)
            if isinstance(type_, type) and issubclass(type_, Structure):
                ret[field] = value._parent_.as_dict(value)
            elif hasattr(value, "__getitem__"):
                ret[field] = value[:]
            else:
                ret[field] = value
        return ret

    @classmethod
    def from_buffer_copy(cls, buf):
        obj = cls()
        obj.values = obj.klass.from_buffer_copy(buf)
        return obj

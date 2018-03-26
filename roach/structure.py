# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import ctypes

from roach.string.bin import (
    IntWorker, Int8, UInt8, Int16, UInt16, Int32, UInt32, Int64, UInt64
)

mapping = {
    Int8: ctypes.c_byte,
    UInt8: ctypes.c_ubyte,
    Int16: ctypes.c_short,
    UInt16: ctypes.c_ushort,
    Int32: ctypes.c_int,
    UInt32: ctypes.c_uint,
    Int64: ctypes.c_longlong,
    UInt64: ctypes.c_ulonglong,
}

class Structure(object):
    # TODO Default value in Python, should we change this to 1?
    _pack_ = 0
    _fields_ = []

    def __init__(self):
        self.subfields, fields = {}, []
        for field, type_ in self._fields_:
            if isinstance(type_, IntWorker):
                if type_.mul:
                    type_ = mapping[type_.__class__] * type_.mul
                else:
                    type_ = mapping[type_.__class__]
            elif isinstance(type_, (int, long)):
                type_ = ctypes.c_char * type_
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
        ret = getattr(self.values, item)
        # Allow caller to omit the [:] part.
        if hasattr(ret, "__getitem__"):
            return ret[:]
        return ret

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
    def sizeof(cls):
        return ctypes.sizeof(cls().klass)

    @classmethod
    def from_buffer_copy(cls, buf):
        obj = cls()
        obj.values = obj.klass.from_buffer_copy(buf)
        return obj

    parse = from_buffer_copy

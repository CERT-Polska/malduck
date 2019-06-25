from ..native.aplib import unpack


class aPLib(object):
    def decompress(self, buf, length=None):
        return unpack(buf, length)

    __call__ = decompress

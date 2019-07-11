from .components.lznt1 import decompress_data


class Lznt1(object):
    """
    Implementation of LZNT1 decompression. Allows to decompress data compressed by RtlCompressBuffer
    """
    def decompress(self, buf):
        return decompress_data(buf)

    __call__ = decompress

from .components.lznt1 import decompress_data


class Lznt1(object):
    """
    Implementation of LZNT1 decompression. Allows to decompress data compressed by RtlCompressBuffer

    .. code-block:: python

        from malduck import lznt1

        lznt1(b"\x1a\xb0\x00compress\x00edtestda\x04ta\x07\x88alot")

    :param buf: Buffer to decompress
    :type buf: bytes
    """
    def decompress(self, buf):
        return decompress_data(buf)

    __call__ = decompress

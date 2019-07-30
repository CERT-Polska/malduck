from .components.aplib import ap_depack
import struct
import warnings


class aPLib(object):
    """
    aPLib decompression

    :param buf: Buffer to decompress
    :type buf: bytes
    :param headerless: Force headerless decompression (don't perform 'AP32' magic detection)
    :type headerless: bool (default: `True`)

    .. versionchanged:: 2.0
        `length` argument is deprecated
    """
    def decompress(self, buf, length=None, headerless=False):
        if length is not None:
            warnings.warn("Length argument is ignored by aPLib.decompress")
        try:
            # Trim header
            if not headerless and buf.startswith(b"AP32"):
                hdr_length = struct.unpack_from("<I", buf, 4)[0]
                buf = buf[hdr_length:]
            # Decompress aPLib
            return ap_depack(buf)
        except Exception as e:
            return None

    __call__ = decompress

from .components.aplib import ap_depack
from ..py2compat import binary_type

import logging
import struct

__all__ = ["aPLib", "aplib"]

log = logging.getLogger(__name__)


class aPLib(object):
    r"""
    aPLib decompression

    .. versionchanged:: 2.0
        `length` argument is deprecated

    .. code-block:: python

        from malduck import aplib

        # Headerless compressed buffer
        aplib(b'T\x00he quick\xecb\x0erown\xcef\xaex\x80jumps\xed\xe4veur`t?lazy\xead\xfeg\xc0\x00')
        # Header included
        aplib(b'AP32\x18\x00\x00\x00\r\x00\x00\x00\xbc\x9ab\x9b\x0b\x00\x00\x00\x85\x11J\rh8el\x8eo wnr\xecd\x00')

    :param buf: Buffer to decompress
    :type buf: bytes
    :param headerless: Force headerless decompression (don't perform 'AP32' magic detection)
    :type headerless: bool (default: `True`)
    :rtype: bytes
    """

    def decompress(self, buf, length=None, headerless=False):
        if length is not None:
            log.warning("Length argument is ignored by aPLib.decompress")
        try:
            # Trim header
            if not headerless and buf.startswith(b"AP32"):
                hdr_length = struct.unpack_from("<I", buf, 4)[0]
                buf = buf[hdr_length:]
            # Decompress aPLib
            return binary_type(ap_depack(buf))
        except Exception:
            return None

    __call__ = decompress


aplib = aPLib()

import logging
import struct
from binascii import crc32
from typing import Optional

from .components.aplib import APLib

__all__ = ["aPLib", "aplib"]

log = logging.getLogger(__name__)


class aPLib:
    r"""
    aPLib decompression

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

    def decompress(self, buf: bytes, headerless: bool = True) -> Optional[bytes]:
        packed_size = None
        packed_crc = None
        orig_size = None
        orig_crc = None
        strict = not headerless

        if buf.startswith(b"AP32") and len(buf) >= 24:
            # buf has an aPLib header
            (
                header_size,
                packed_size,
                packed_crc,
                orig_size,
                orig_crc,
            ) = struct.unpack_from("=IIIII", buf, 4)
            buf = buf[header_size : header_size + packed_size]

        if strict:
            if packed_size is not None and packed_size != len(buf):
                raise RuntimeError("Packed buf size is incorrect")
            if packed_crc is not None and packed_crc != crc32(buf):
                raise RuntimeError("Packed buf checksum is incorrect")

        result = APLib(buf, strict=strict).depack()

        if strict:
            if orig_size is not None and orig_size != len(result):
                raise RuntimeError("Unpacked buf size is incorrect")
            if orig_crc is not None and orig_crc != crc32(result):
                raise RuntimeError("Unpacked buf checksum is incorrect")

        return result

    __call__ = decompress


aplib = aPLib()

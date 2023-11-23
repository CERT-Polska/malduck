from __future__ import annotations

import operator
from itertools import cycle, starmap
from sys import byteorder

__all__ = ["xor"]


def xor(key: int | bytes, data: bytes) -> bytes:
    """
    XOR encryption/decryption

    :param key: Encryption key
    :type key: int (single byte) or bytes
    :param data: Buffer containing data to decrypt
    :type data: bytes
    :return: Encrypted/decrypted data
    :rtype: bytes
    """
    if isinstance(key, int):
        key = key.to_bytes(1, byteorder)  # generally faster than bytes([key])
    return bytes(starmap(operator.xor, zip(data, cycle(key))))

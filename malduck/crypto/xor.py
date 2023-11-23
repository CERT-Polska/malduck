from __future__ import annotations

from itertools import cycle

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
        key = bytes([key])
    return bytes([a ^ b for a, b in zip(data, cycle(key))])

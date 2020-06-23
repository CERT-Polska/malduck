from itertools import cycle

from typing import Union

__all__ = ["xor"]


def xor(key: Union[int, bytes], data: bytes) -> bytes:
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

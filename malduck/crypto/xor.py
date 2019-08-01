from itertools import cycle

from ..py2compat import is_integer, int2byte, iterbytes_ord


def xor(key, data):
    """
    XOR decryption

    :param key: Encryption key
    :type key: int or bytes
    :param data: Buffer containing data to decrypt
    :type data: bytes
    :return:
    """
    if is_integer(key):
        key = int2byte(key)
    return b"".join(int2byte(a ^ b) for a, b in zip(
        iterbytes_ord(data),
        cycle(iterbytes_ord(key))
    ))

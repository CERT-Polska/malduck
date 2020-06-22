from itertools import cycle

from ..py2compat import is_integer, int2byte, iterbytes_ord

__all__ = ["xor"]


class XOR(object):
    """
    XOR encryption/decryption

    :param key: Encryption key
    :type key: int (single byte) or bytes
    :param data: Buffer containing data to decrypt
    :type data: bytes
    :return: Encrypted/decrypted data
    :rtype: bytes
    """

    def __call__(self, key, data):
        if is_integer(key):
            key = int2byte(key)
        return b"".join(
            int2byte(a ^ b)
            for a, b in zip(iterbytes_ord(data), cycle(iterbytes_ord(key)))
        )

    encrypt = decrypt = __call__


xor = XOR()

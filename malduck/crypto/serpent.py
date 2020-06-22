import warnings

from .components.pyserpent import serpent_cbc_encrypt, serpent_cbc_decrypt

__all__ = ["Serpent", "serpent"]


class SerpentCbc(object):
    def encrypt(self, key, data, iv=None):
        """
        Encrypts buffer using Serpent algorithm in CBC mode.

        :param key: Cryptographic key (4-32 bytes, must be multiple of four)
        :type key: bytes
        :param data: Buffer to be encrypted
        :type data: bytes
        :param iv: Initialization vector (defaults to `b"\x00" * 16`)
        :type iv: bytes, optional
        :return: Encrypted data
        :rtype: bytes
        """
        return serpent_cbc_encrypt(key, data, iv=iv or b"\x00" * 16)

    def decrypt(self, key, data, iv=None):
        """
        Decrypts buffer using Serpent algorithm in CBC mode.

        :param key: Cryptographic key (4-32 bytes, must be multiple of four)
        :type key: bytes
        :param data: Buffer to be decrypted
        :type data: bytes
        :param iv: Initialization vector (defaults to `b"\x00" * 16`)
        :type iv: bytes, optional
        :return: Decrypted data
        :rtype: bytes
        """
        return serpent_cbc_decrypt(key, data, iv=iv or b"\x00" * 16)


class _Serpent(object):
    cbc = SerpentCbc()

    def encrypt(self, key, data, iv=None):
        warnings.warn(
            "malduck.serpent.encrypt is deprecated, please use malduck.serpent.cbc.encrypt",
            DeprecationWarning,
        )
        return self.cbc.encrypt(key, data, iv=iv)

    def decrypt(self, key, data, iv=None):
        warnings.warn(
            "malduck.serpent.decrypt is deprecated, please use malduck.serpent.cbc.decrypt",
            DeprecationWarning,
        )
        return self.cbc.decrypt(key, data, iv=iv)

    def __call__(self, key, data, iv=None):
        warnings.warn(
            "malduck.serpent() is deprecated, please use malduck.serpent.cbc.decrypt",
            DeprecationWarning,
        )
        return self.cbc.decrypt(key, data, iv=iv)


class Serpent(object):
    def __init__(self, key, iv=None):
        warnings.warn(
            "malduck.crypto.Serpent is deprecated, please use malduck.serpent.<mode> variants",
            DeprecationWarning,
        )
        self.key = key
        self.iv = iv or b"\x00" * 16

    def decrypt(self, data):
        return _Serpent.cbc.decrypt(self.key, data, iv=self.iv)

    def encrypt(self, data):
        return _Serpent.cbc.encrypt(self.key, data, iv=self.iv)


serpent = _Serpent()

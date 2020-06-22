from typing import Optional

from .components.pyserpent import serpent_cbc_encrypt, serpent_cbc_decrypt

__all__ = ["serpent"]


class SerpentCbc:
    def encrypt(self, key: bytes, data: bytes, iv: Optional[bytes] = None) -> bytes:
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

    def decrypt(self, key: bytes, data: bytes, iv: Optional[bytes] = None) -> bytes:
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


class Serpent:
    cbc = SerpentCbc()


serpent = Serpent()

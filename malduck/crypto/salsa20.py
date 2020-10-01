from typing import Optional
from Cryptodome.Cipher import Salsa20 as Salsa20Cipher


__all__ = ["salsa20"]


class Salsa20:
    def encrypt(self, key: bytes, data: bytes, nonce: Optional[bytes] = None) -> bytes:
        """
        Encrypts buffer using Salsa20 algorithm.

        :param key: Cryptographic key (16/32 bytes)
        :type key: bytes
        :param data: Buffer to be encrypted
        :type data: bytes
        :param nonce: Nonce value (8 bytes, defaults to `b"\\\\x00"*8` )
        :type nonce: bytes, optional
        :return: Encrypted data
        :rtype: bytes
        """
        if nonce is None:
            nonce = b"\x00" * 8
        return Salsa20Cipher.new(key=key, nonce=nonce).encrypt(data)

    def decrypt(self, key: bytes, data: bytes, nonce: Optional[bytes] = None) -> bytes:
        """
        Decrypts buffer using Salsa20 algorithm.

        :param key: Cryptographic key (16/32 bytes)
        :type key: bytes
        :param data: Buffer to be decrypted
        :type data: bytes
        :param nonce: Nonce value (8 bytes, defaults to `b"\\\\x00"*8` )
        :type nonce: bytes, optional
        :return: Decrypted data
        :rtype: bytes
        """
        if nonce is None:
            nonce = b"\x00" * 8
        return Salsa20Cipher.new(key=key, nonce=nonce).decrypt(data)


salsa20 = Salsa20()

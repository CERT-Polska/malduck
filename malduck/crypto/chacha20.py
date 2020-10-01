from typing import Optional
from Cryptodome.Cipher import ChaCha20 as ChaCha20Cipher


__all__ = ["chacha20"]


class ChaCha20:
    def encrypt(self, key: bytes, data: bytes, nonce: Optional[bytes] = None) -> bytes:
        """
        Encrypts buffer using ChaCha20 algorithm.

        :param key: Cryptographic key (32 bytes)
        :type key: bytes
        :param data: Buffer to be encrypted
        :type data: bytes
        :param nonce: Nonce value (8/12 bytes, defaults to `b"\\\\x00"*8` )
        :type nonce: bytes, optional
        :return: Encrypted data
        :rtype: bytes
        """
        if nonce is None:
            nonce = b"\x00" * 8
        return ChaCha20Cipher.new(key=key, nonce=nonce).encrypt(data)

    def decrypt(self, key: bytes, data: bytes, nonce: Optional[bytes] = None) -> bytes:
        """
        Decrypts buffer using ChaCha20 algorithm.

        :param key: Cryptographic key (32 bytes)
        :type key: bytes
        :param data: Buffer to be decrypted
        :type data: bytes
        :param nonce: Nonce value (8/12 bytes, defaults to `b"\\\\x00"*8` )
        :type nonce: bytes, optional
        :return: Decrypted data
        :rtype: bytes
        """
        if nonce is None:
            nonce = b"\x00" * 8
        return ChaCha20Cipher.new(key=key, nonce=nonce).decrypt(data)


chacha20 = ChaCha20()

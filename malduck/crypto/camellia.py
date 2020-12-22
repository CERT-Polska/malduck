from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


__all__ = ["camellia"]


class CamelliaCbc:
    def encrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        """
        Encrypts buffer using Camellia algorithm in CBC mode.

        :param key: Cryptographic key (128, 192 or 256 bits)
        :type key: bytes
        :param iv: Initialization vector
        :type iv: bytes
        :param data: Buffer to be encrypted
        :type data: bytes
        :return: Encrypted data
        :rtype: bytes
        """
        algo = algorithms.Camellia(key)
        cipher = Cipher(algo, modes.CBC(iv))
        enc = cipher.encryptor()
        return enc.update(data) + enc.finalize()

    def decrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        """
        Decrypts buffer using Camellia algorithm in CBC mode.

        :param key: Cryptographic key (128, 192 or 256 bits)
        :type key: bytes
        :param iv: Initialization vector
        :type iv: bytes
        :param data: Buffer to be decrypted
        :type data: bytes
        :return: Decrypted data
        :rtype: bytes
        """
        algo = algorithms.Camellia(key)
        cipher = Cipher(algo, modes.CBC(iv))
        dec = cipher.decryptor()
        return dec.update(data) + dec.finalize()


class CamelliaCfb:
    def encrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        """
        Encrypts buffer using Camellia algorithm in CFB mode.

        :param key: Cryptographic key (128, 192 or 256 bits)
        :type key: bytes
        :param iv: Initialization vector
        :type iv: bytes
        :param data: Buffer to be encrypted
        :type data: bytes
        :return: Encrypted data
        :rtype: bytes
        """
        algo = algorithms.Camellia(key)
        cipher = Cipher(algo, modes.CFB(iv))
        enc = cipher.encryptor()
        return enc.update(data) + enc.finalize()

    def decrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        """
        Decrypts buffer using Camellia algorithm in CFB mode.

        :param key: Cryptographic key (128, 192 or 256 bits)
        :type key: bytes
        :param iv: Initialization vector
        :type iv: bytes
        :param data: Buffer to be decrypted
        :type data: bytes
        :return: Decrypted data
        :rtype: bytes
        """
        algo = algorithms.Camellia(key)
        cipher = Cipher(algo, modes.CFB(iv))
        dec = cipher.decryptor()
        return dec.update(data) + dec.finalize()


class CamelliaOfb:
    def encrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        """
        Encrypts buffer using Camellia algorithm in OFB mode.

        :param key: Cryptographic key (128, 192 or 256 bits)
        :type key: bytes
        :param iv: Initialization vector
        :type iv: bytes
        :param data: Buffer to be encrypted
        :type data: bytes
        :return: Encrypted data
        :rtype: bytes
        """
        algo = algorithms.Camellia(key)
        cipher = Cipher(algo, modes.OFB(iv))
        enc = cipher.encryptor()
        return enc.update(data) + enc.finalize()

    def decrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        """
        Decrypts buffer using Camellia algorithm in OFB mode.

        :param key: Cryptographic key (128, 192 or 256 bits)
        :type key: bytes
        :param iv: Initialization vector
        :type iv: bytes
        :param data: Buffer to be decrypted
        :type data: bytes
        :return: Decrypted data
        :rtype: bytes
        """
        algo = algorithms.Camellia(key)
        cipher = Cipher(algo, modes.OFB(iv))
        dec = cipher.decryptor()
        return dec.update(data) + dec.finalize()


class CamelliaEcb:
    def encrypt(self, key: bytes, data: bytes) -> bytes:
        """
        Encrypts buffer using Camellia algorithm in ECB mode.

        :param key: Cryptographic key (128, 192 or 256 bits)
        :type key: bytes
        :param data: Buffer to be encrypted
        :type data: bytes
        :return: Encrypted data
        :rtype: bytes
        """
        algo = algorithms.Camellia(key)
        cipher = Cipher(algo, modes.ECB())
        enc = cipher.encryptor()
        return enc.update(data) + enc.finalize()

    def decrypt(self, key: bytes, data: bytes) -> bytes:
        """
        Decrypts buffer using Camellia algorithm in ECB mode.

        :param key: Cryptographic key (128, 192 or 256 bits)
        :type key: bytes
        :param data: Buffer to be decrypted
        :type data: bytes
        :return: Decrypted data
        :rtype: bytes
        """
        algo = algorithms.Camellia(key)
        cipher = Cipher(algo, modes.ECB())
        dec = cipher.decryptor()
        return dec.update(data) + dec.finalize()


class CamelliaCtr:
    def encrypt(self, key: bytes, nonce: bytes, data: bytes) -> bytes:
        """
        Encrypts buffer using Camellia algorithm in CTR mode.

        :param key: Cryptographic key (128, 192 or 256 bits)
        :type key: bytes
        :param nonce: Initial counter value, big-endian encoded
        :type nonce: bytes
        :param data: Buffer to be encrypted
        :type data: bytes
        :return: Encrypted data
        :rtype: bytes
        """
        algo = algorithms.Camellia(key)
        cipher = Cipher(algo, modes.CTR(nonce))
        enc = cipher.encryptor()
        return enc.update(data) + enc.finalize()

    def decrypt(self, key: bytes, nonce: bytes, data: bytes) -> bytes:
        """
        Decrypts buffer using Camellia algorithm in CTR mode.

        :param key: Cryptographic key (128, 192 or 256 bits)
        :type key: bytes
        :param nonce: Initial counter value, big-endian encoded
        :type nonce: bytes
        :param data: Buffer to be decrypted
        :type data: bytes
        :return: Decrypted data
        :rtype: bytes
        """
        algo = algorithms.Camellia(key)
        cipher = Cipher(algo, modes.CTR(nonce))
        dec = cipher.decryptor()
        return dec.update(data) + dec.finalize()


class Camellia:
    cbc = CamelliaCbc()
    ecb = CamelliaEcb()
    ctr = CamelliaCtr()
    cfb = CamelliaCfb()
    ofb = CamelliaOfb()


camellia = Camellia()

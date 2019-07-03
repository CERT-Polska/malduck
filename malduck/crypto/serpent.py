from .components.pyserpent import serpent_cbc_encrypt, serpent_cbc_decrypt


class Serpent(object):
    def __init__(self, key, iv=None):
        self.key = key
        self.iv = iv or b"\x00" * 16

    def decrypt(self, data):
        return serpent_cbc_decrypt(self.key, data, iv=self.iv)

    def encrypt(self, data):
        return serpent_cbc_encrypt(self.key, data, iv=self.iv)

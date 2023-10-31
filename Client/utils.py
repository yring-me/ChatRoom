import string
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number
import base64
import math

import gmpy2


class Client_DH:
    def __init__(self):
        self.rand_p = number.getPrime(512)
        self.rand_g = self.root(self.rand_p)
        self.private_key = random.randint(1, 0xffffffffffffffff)
        self.self_public_key = pow(self.rand_g, self.private_key, self.rand_p)

        self.share_key = 0

    @staticmethod
    def root(n):  # 这样默认求最小原根
        k = math.floor((n - 1) / 2)
        for i in range(2, n - 1):
            if pow(i, k, n) != 1:
                return i

    def calc_share_key(self, oppo_public_key):
        self.share_key = pow(oppo_public_key, self.private_key, self.rand_p)


class Client_AES:
    def __init__(self, aes_key, aes_iv):
        self.plain_text = None
        self.aes_key = aes_key
        self.aes_iv = aes_iv
        self.size = 16

        self.cipher_text = None

    def get_random_digits(self):
        """Generate random number by size"""
        return "".join(random.choice(string.digits) for i in range(self.size))

    def aes_encrypt(self, plain_text):
        """
        AES encrypt
        :param plain_text: bytes
        :param aes_key: bytes
        :param aes_iv: bytes
        :return: bytes
        """
        self.plain_text = plain_text
        return AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv).encrypt(pad(plain_text, AES.block_size))


    def aes_decrypt(self, cipher_text):
        """
        AES decrypt
        :param cipher_text:
        :param plain_text: bytes
        :param aes_key: bytes, aes_key
        :param aes_iv: bytes, aes_iv
        :return: bytes
        """
        self.cipher_text = cipher_text
        return unpad(AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv).decrypt(cipher_text), AES.block_size)

    @staticmethod
    def get_prime_num():
        return number.getPrime(512)


class Client_RSA:
    def __init__(self, p, q):
        self.p = p
        self.q = q
        self.n = p * q
        self.phi = (p-1)*(q-1)
        self.e = 65537

        self.d = gmpy2.invert(self.e, self.phi)

    def rsa_encrypt(self, plain_text):
        """
        :param plain_text: int
        :return: int
        """
        cipher_text = pow(plain_text, self.e, self.n)
        return cipher_text

    def rsa_decrypt(self, cipher_text):
        plain_text = pow(cipher_text, self.d, self.n)
        return plain_text


if __name__ == '__main__':
    p = number.getPrime(256)
    q = number.getPrime(256)
    rsa = Client_RSA(p, q)
    t = rsa.rsa_encrypt(123)
    print(rsa.rsa_decrypt(t))

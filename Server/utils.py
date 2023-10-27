import string
import base64
import random

import gmpy2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number
import math


class Server_DH:
    def __init__(self, client_p, client_g):
        self.rand_p = client_p
        self.rand_g = client_g
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


class Server_AES:
    def __init__(self, aes_key, aes_iv):
        self.plain_text = None
        self.aes_key = aes_key
        self.aes_iv = aes_iv
        self.size = 16

        self.cipher_text = None

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


class Sever_RSA:
    def __init__(self):
        self.p = number.getPrime(512)
        self.q = number.getPrime(512)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.e = self.set_e()

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

    def set_e(self):
        for i in range(65537, self.n):
            if gmpy2.gcd(i, self.phi) == 1:
                return i
            continue


if __name__ == '__main__':
    rsa = Sever_RSA()
    t = rsa.rsa_encrypt(123123123123123)
    print(rsa.d)
    print(rsa.rsa_decrypt(t))

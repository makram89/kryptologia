from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad as padding

# Padding for the input string --not
# related to encryption itself.
BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class AESCipher:
    """
    Usage:
        c = AESCipher('password').encrypt('message')
        m = AESCipher('password').decrypt(c)
    Tested under Python 3 and PyCrypto 2.6.1.
    """

    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def encrypt(self, raw):
        raw = padding(raw, 16)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        cipher_txt = cipher.encrypt(raw)
        return b64encode(cipher_txt)

    def decrypt(self, enc, iv):
        enc = b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc)).decode('ascii')

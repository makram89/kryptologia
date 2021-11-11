import json
from sys import argv

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket
import requests
import base64


class Client:
    # PORT = 6666
    URL_BOB = 'http://150.254.79.213:6666/msg/'
    URL = 'http://150.254.79.212:5000/get_key/alice/bob/'

    KEY_A = bytes("01010101010101010101010101010101", "ascii")
    KEY_K = ""

    def get_K(self):
        # request o uzyskanie K

        # sending get request and saving the response as response object
        r = requests.get(url=self.URL)

        # extracting data in json format
        data = r.json()

        #  Odebranie Ca, Cb, C
        Ca = data["Ca"]
        Cb = data["Cb"]
        C = data["C"]

        # usunięcie paddingu i rozszyfrowanie klucza sesyjnego
        result = unpad(self.decrypt(base64.b64decode(Ca), self.KEY_A), 16).decode("ascii")
        self.KEY_K = bytes(result, "ascii")

        print("Decoded key: ")
        print(result)

        return result, C, Cb

    @staticmethod
    def decrypt(c, key):
        d_content = AES.new(key, AES.MODE_ECB).decrypt(c)
        return d_content


def main():
    client = Client()
    key, C, Cb = client.get_K()
    with open("session.key", "w") as F:
        json.dump({
            "key": key,
            "C": C,
            "Cb": Cb
        }, F)

main()

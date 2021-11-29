import json
from sys import argv

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket
import requests
import base64


class Client:
    # PORT = 6666
#    URL_BOB = 'http://150.254.79.213:6666/msg/'
#    URL = 'http://150.254.79.212:5000/get_key/alice/bob/'

    URL_BOB = 'http://localhost:6666/msg/'
    URL = 'http://localhost:5000/get_key/alice/bob/'

    KEY_A = bytes("01010101010101010101010101010101", "ascii")
    KEY_K = ""

    def get_K(self):
        # request o uzyskanie K

        # sending get request and saving the response as response object
        r = requests.get(url=self.URL)

        data = r.json()

        Ca = data["Ca"][24:]
        Cb = data["Cb"]
        C = data["C"]

        b64iv = data["Ca"][:24]
        iv = base64.b64decode(b64iv)

        # usunięcie paddingu i rozszyfrowanie klucza sesyjnego
        result = unpad(self.decrypt(base64.b64decode(Ca), self.KEY_A, iv), 16).decode("ascii")
        self.KEY_K = bytes(result, "ascii")

        print("Decoded key: ")
        print(result)

        return result, C, Cb

    @staticmethod
    def decrypt(c, key, iv):
        d_content = AES.new(key, AES.MODE_CBC, iv).decrypt(c)
        return d_content


def main():
    client = Client()
    key, C, Cb = client.get_K()
    with open("session.key", "w") as F:
        json.dump({
            "key": key,
            "C": C,
            "Cb": Cb,
        }, F)


if __name__ == '__main__':
    main()

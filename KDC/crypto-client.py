import json
from sys import argv

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import socket
import requests
import base64


class Client:
    # PORT = 6666
    URL_BOB = 'http://150.254.79.213:6666/msg/'

    KEY_A = bytes("01010101010101010101010101010101", "ascii")
    KEY_K = ""
    IV = get_random_bytes(16)

    def get_K(self):
        try:
            with open("session.key", "r") as F:
                keys = json.load(F)
        except:
            print("Obtain session key first!")
            exit(1)

        self.KEY_K = bytes(keys["key"], "ascii")
        Cb = keys["Cb"]
        C = keys["C"]

        return C, Cb

    def send_to_bob(self, json_in):
        headers = {'content-type': 'application/json', 'content-length': str(len(json_in))}
        r = requests.post(self.URL_BOB, json=json_in, headers=headers)

    @staticmethod
    def decrypt(c, key, iv=bytes('', "ascii")):
        d_content = AES.new(key, AES.MODE_CBC, iv).decrypt(c)
        return d_content

    def encrypt_using_session(self, m):
        m = pad(m, 16)
        e_content = AES.new(self.KEY_K, AES.MODE_CBC, self.IV).encrypt(m)
        return base64.b64encode(e_content).decode("ascii")

    @staticmethod
    def prepare_file(file_path):
        file = open(file_path, 'rb')
        content = file.read()
        file.close()
        return content

    # Zwraca bytes w codowaniu base64
    def get_iv(self):
        return base64.b64encode(self.IV)


def main():
    client = Client()
    C, Cb = client.get_K()
    path = argv[1]
    raw = client.prepare_file(path)
    Cm = client.encrypt_using_session(raw)
    Cn = client.encrypt_using_session(bytes(path.split('/')[-1], "ascii"))

    j_dict = {"Cm": Cm,
              "C": C,
              "Cb": Cb,
              "Cn": Cn,
              "iv": client.get_iv()
              }
    json_msg = json.dumps(j_dict)

    client.send_to_bob(json_msg)


main()

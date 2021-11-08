import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket
import requests
import base64


class Client:
    # PORT = 6666
    URL_BOB = 'http://127.0.0.1:6666/msg/'
    URL = 'http://localhost:5000/get_key/alice/bob/'

    KEY_A = bytes("01010101010101010101010101010101", "ascii")
    KEY_K = ""
    # Alice/Bob
    ID = "A"

    def __init__(self):
        pass

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

        return C, Cb

    # TODO uruchomić serwer flaskowy
    def listen(self):
        pass

    def send_to_bob(self, json_in):
        headers = {'content-type': 'application/json', 'content-length': str(len(json_in))}
        r = requests.post(self.URL_BOB, json=json_in, headers=headers)
        print(r.url)

    @staticmethod
    def decrypt(c, key, iv=''):
        d_content = AES.new(key, AES.MODE_ECB).decrypt(c)
        return d_content

    def encrypt_using_session(self, m, iv=''):
        m = pad(m, 16)
        e_content = AES.new(self.KEY_K, AES.MODE_ECB).encrypt(m)
        return base64.b64encode(e_content).decode("ascii")

    # TODO obsłużyć plik i jego zamiane
    @staticmethod
    def prepare_file(file_path):
        file = open(file_path, 'rb')
        #  Plik / block size
        content = pad(file.read(), 16)
        file.close()
        return content


# TODO Ogólnie odpalanie klienta w 2 trybach -> obecny main wysyła wiadomość i tyle
def main():
    client = Client()
    C, Cb = client.get_K()
    Cm = client.encrypt_using_session(bytes("eloelo", "ascii"))
    j_dict = {"Cm": Cm,
              "C": C,
              "Cb": Cb
              }
    json_msg = json.dumps(j_dict)

    client.send_to_bob(json_msg)


main()

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import requests
import base64


class Client:
    PORT = 5000
    HOST = '127.0.0.1'
    URL = 'http://localhost:5000/get_key/alice/bob/'

    KEY_A = bytes("01010101010101010101010101010101", "ascii")
    KEY_K = get_random_bytes(256)
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

        result = unpad(self.decrypt(base64.b64decode(Ca), self.KEY_A),16).decode("ascii")

        print(result)
        self.KEY_K = result
        print("decoded key: ")

        return C, Cb

    def listen(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.HOST, self.PORT))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    conn.sendall(data)

    @staticmethod
    def decrypt(c, key, iv=''):
        d_content = AES.new(key, AES.MODE_ECB).decrypt(c)
        return d_content

    @staticmethod
    def encrypt(m, key, iv=''):
        e_content = AES.new(key, AES.MODE_ECB).encrypt(m)
        return e_content

    @staticmethod
    def prepare_file(file_path):
        file = open(file_path, 'rb')
        #  Plik / block size
        content = pad(file.read(), 16)
        file.close()
        return content


def main():
    client = Client()
    client.get_K()


main()

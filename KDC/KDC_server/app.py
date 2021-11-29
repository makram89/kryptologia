import random
from aes import AESCipher
from flask import Flask
from Crypto.Random import get_random_bytes
from base64 import b64encode

app = Flask(__name__)
k_len = 32
PERSONAL_KEYS = {
    "alice": bytes("01" * (k_len//2), 'ascii'),
    "bob": bytes("10" * (k_len//2), 'ascii')
}


@app.route('/get_key/<string:requester>/<string:name>/')
def get_key(requester, name):  # put application's code here
    session_key = bytes(''.join([str(random.randint(0, 1)) for _ in range(k_len)]), 'ascii')

    print(PERSONAL_KEYS)
    print("Session key: ", session_key.decode("ascii"))

    iv = get_random_bytes(16)
    b64iv = b64encode(iv).decode('ascii')

    requester_key = PERSONAL_KEYS.get(requester, '0')
    adresee_key = PERSONAL_KEYS.get(name, '0')
    return {
        "Ca": b64iv + AESCipher(requester_key, iv).encrypt(session_key).decode("ascii"),
        "Cb":  b64iv + AESCipher(adresee_key, iv).encrypt(session_key).decode("ascii"),
        "C": b64iv + AESCipher(adresee_key, iv).encrypt(bytes(requester, 'ascii')).decode("ascii"),
    }


if __name__ == '__main__':
    app.run()

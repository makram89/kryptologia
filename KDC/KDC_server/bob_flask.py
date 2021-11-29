from flask import Flask, redirect, url_for, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json

app = Flask(__name__)

BOB_KEY = bytes("10" * 16, 'ascii')


def decrypt(c, key, iv):
    d_content = AES.new(key, AES.MODE_CBC, iv).decrypt(c)
    return d_content


@app.route('/msg/', methods=['POST'])
def get_msg():
    if request.method == 'POST':
        content = json.loads(request.json)
        iv1 = base64.b64decode(content["Cb"][:24])
        Cb = content["Cb"][24:]
        C = content["C"][24:]
        iv2 = base64.b64decode(content["Cm"][:24])
        Cm = content["Cm"][24:]

        session_key = unpad(decrypt(base64.b64decode(Cb), BOB_KEY, iv1), 16)
        # session_key = bytes(session_key, "ascii")

        message = unpad(decrypt(base64.b64decode(Cm), session_key, iv2), 16)
        fname = "test.png"
        # fname = unpad(decrypt(base64.b64decode(Cn), session_key), 16).decode("ascii")
        sender = unpad(decrypt(base64.b64decode(C), BOB_KEY, iv1), 16).decode("ascii")

        with open(fname, "wb") as F:
            F.write(message)

        print("From: ", sender)

        return {'success': True}, 200, {'ContentType': 'application/json'}


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6666)

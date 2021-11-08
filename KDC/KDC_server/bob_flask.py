from flask import Flask, redirect, url_for, request
import json


app = Flask(__name__)


@app.route('/msg/', methods=['POST'])
def get_msg():
    if request.method == 'POST':
        content = request.json
        print(content)
        return json.dumps({'success': True}), 200, {'ContentType':'application/json'}
#     TODO obsłużyć odczyt danych (i ich odszyfrowanie)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=6666)

import datetime

import common
from flask import Flask, request, send_file
from flask_cors import CORS
from generate_broken_qr import generate_broken_qr
from generate_malicious_qr import generate_malicious_qr

ECC_LEVEL = {0: "LOW", 1: "MEDIUM", 2: "QUARTILE", 3: "HIGH"}

app = Flask(__name__)
CORS(app)


@app.route("/api/tamper", methods=["GET"])
def tamper():
    message = request.args.get("message")
    version = abs(int(request.args.get("version")))
    ecc = request.args.get("ecc")
    ecc = ECC_LEVEL[abs(int(ecc))]
    mask = abs(int(request.args.get("mask")))

    print("MESSAGE: ", message)
    print("VERSION: ", version)
    print("ECC: ", ecc)
    print("MASK: ", mask)

    filename = str(datetime.datetime.now())
    print("FILENAME: ", filename)

    output_path = generate_malicious_qr(message, ecc, version, mask, filename)
    malicious_message = ""
    with open("demo/" + output_path.replace("diff_", "") + ".txt", "r") as file:
        malicious_message = file.readlines()
    print("MESSAGE: ", malicious_message)

    return malicious_message[0] + "\n" + output_path


@app.route("/api/destroy", methods=["GET"])
def destroy():
    message = request.args.get("message")
    version = abs(int(request.args.get("version")))
    ecc = request.args.get("ecc")
    ecc = ECC_LEVEL[abs(int(ecc))]
    mask = abs(int(request.args.get("mask")))

    print("MESSAGE: ", message)
    print("VERSION: ", version)
    print("ECC: ", ecc)
    print("MASK: ", mask)

    filename = str(datetime.datetime.now())
    print("FILENAME: ", filename)

    output_path = generate_broken_qr(message, ecc, version, mask, filename)
    return send_file(output_path, mimetype="image/png")


@app.route("/api/get_image", methods=["GET"])
def get_image():
    name = request.args.get("name")
    return send_file("demo/" + name + ".png", mimetype="image/png")


if __name__ == "__main__":
    common.init_pool(num_processes=1)
    try:
        app.run(host="127.0.0.1", port=8080)
    except KeyboardInterrupt:
        if common.POOL:
            common.POOL.terminate()
            common.POOL.join()

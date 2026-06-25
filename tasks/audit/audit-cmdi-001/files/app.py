import subprocess

from flask import Flask, request


app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    count = request.args.get("count", "1")
    command = "ping -n " + count + " " + host
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=5)
    return "<pre>" + output.decode(errors="replace") + "</pre>"


if __name__ == "__main__":
    app.run(debug=True)

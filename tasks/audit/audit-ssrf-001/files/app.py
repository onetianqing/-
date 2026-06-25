from flask import Flask, Response, request
import requests


app = Flask(__name__)


@app.route("/")
def index():
    return "Use /fetch?url=https://example.com"


@app.route("/fetch")
def fetch_url():
    target = request.args.get("url", "")
    if not target.startswith(("http://", "https://")):
        return "unsupported scheme", 400

    response = requests.get(target, timeout=3)
    content_type = response.headers.get("content-type", "text/plain")
    return Response(response.text[:4096], content_type=content_type)


if __name__ == "__main__":
    app.run(debug=True)

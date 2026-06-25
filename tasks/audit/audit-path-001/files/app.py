from pathlib import Path

from flask import Flask, request, send_file


app = Flask(__name__)
UPLOAD_DIR = Path(__file__).parent / "uploads"


@app.route("/download")
def download():
    name = request.args.get("name", "readme.txt")
    full_path = UPLOAD_DIR / name
    if not full_path.exists():
        return "not found", 404
    return send_file(full_path)


if __name__ == "__main__":
    app.run(debug=True)

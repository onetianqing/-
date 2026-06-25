import sqlite3

from flask import Flask, redirect, render_template_string, request, session


app = Flask(__name__)
app.secret_key = "dev-only-secret"


LOGIN_PAGE = """
<form method="post">
  <input name="username" placeholder="username">
  <input name="password" placeholder="password" type="password">
  <button type="submit">login</button>
</form>
"""


def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_PAGE)

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    query = (
        "SELECT id, username FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )

    row = get_db().execute(query).fetchone()
    if row:
        session["user_id"] = row["id"]
        return redirect("/profile")

    return "invalid credentials", 401


@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect("/login")
    return "hello user"


if __name__ == "__main__":
    app.run(debug=True)

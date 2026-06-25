const express = require("express");

const app = express();
app.use(express.json());

function queryDatabase(sql) {
  console.log("SQL:", sql);
  return [];
}

app.post("/rest/user/login", function login(req, res) {
  const email = req.body.email || "";
  const password = req.body.password || "";
  const sql =
    "SELECT * FROM Users WHERE email = '" +
    email +
    "' AND password = '" +
    password +
    "'";

  const rows = queryDatabase(sql);
  if (rows.length > 0) {
    return res.json({ authentication: { token: "local-demo-token" } });
  }
  return res.status(401).json({ error: "Invalid email or password." });
});

module.exports = app;

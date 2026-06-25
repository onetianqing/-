const express = require("express");

const app = express();

app.get("/", (req, res) => {
  res.send("<a href='/search?q=test'>search</a>");
});

app.get("/search", (req, res) => {
  const q = req.query.q || "";
  res.set("Content-Type", "text/html");
  res.send(`<h1>Search results for: ${q}</h1>`);
});

app.listen(3000, () => {
  console.log("listening on http://localhost:3000");
});

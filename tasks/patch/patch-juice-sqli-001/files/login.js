// Minimal login data-access example adapted for security patch evaluation.
// It intentionally keeps only the vulnerable pattern needed by the task.

function login(db, email, password, done) {
  if (!email || !password) {
    return done(new Error("missing credentials"));
  }

  const query =
    "SELECT * FROM Users WHERE email = '" +
    email +
    "' AND password = '" +
    password +
    "'";

  return db.get(query, done);
}

module.exports = { login };

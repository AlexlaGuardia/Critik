// Hardened config — secure cookies, no eval, no dev mode. Should NOT flag.
const express = require("express");
const app = express();

app.use(
  require("express-session")({
    secret: process.env.SESSION_SECRET,
    cookie: { secure: true, httpOnly: true, sameSite: "strict" },
  })
);

// Parse input safely; no eval / document.write / new Function.
function handle(payload) {
  const data = JSON.parse(payload);
  return data.value;
}

app.set("env", "production");

module.exports = { app, handle };

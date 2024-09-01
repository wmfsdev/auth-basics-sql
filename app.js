
const { Pool } = require("pg");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs")
const pgSession = require("connect-pg-simple")(session)
const passport = require("passport");
const LocalStrategy = require('passport-local').Strategy;
const path = require("node:path")
require('dotenv').config()

const pool = new Pool({
  connectionString: process.env.CONNECTION_STRING
});

const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(session({
  store: new pgSession({
    pool: pool,
    createTableIfMissing: true
  }),
  secret: "cats",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
      const user = rows[0];

      const match = await bcrypt.compare(password, user.password);

      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      if (!match) {
        return done(null, false, { message: "Incorrect password" });
      }
      return done(null, user);
    } catch(err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    const user = rows[0];

    done(null, user);
  } catch(err) {
    done(err);
  }
});

app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});

app.get("/", (req, res) => {
  res.render("index", { user: res.locals.currentUser });
});

app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/"
  })
);

app.post("/sign-up", async (req, res, next) => {

    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    try {
      await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [
        req.body.username,
        hashedPassword,
      ]);
      res.redirect("/");
    } catch(err) {
      return next(err);
    }
});

app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.listen(3000, () => console.log("app listening on port 3000!"));

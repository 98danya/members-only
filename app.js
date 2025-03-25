require("dotenv").config();
const path = require("node:path");
const pool = require("./db/pool.js");
const bcrypt = require("bcrypt");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: false }));
app.use(session({ secret: "cats", resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

// Index Page
app.get("/", async (req, res) => {
    try {
      const messages = await pool.query(
        `SELECT messages.*, users.first_name, users.last_name 
         FROM messages 
         JOIN users ON messages.user_id = users.id`
      );
  
      if (req.isAuthenticated()) {
        const { is_member, is_admin, first_name } = req.user;
  
        res.render("index", {
          user: req.user,
          isAuthenticated: true,
          isAdmin: is_admin || false,
          isMember: is_member || false,
          firstName: first_name || "Guest",
          messages: messages.rows,
        });
      } else {
        res.render("index", {
          isAuthenticated: false,
          isAdmin: false,
          isMember: false,
          messages: messages.rows,
        });
      }
    } catch (error) {
      console.error(error);
      res.status(500).send("Error loading messages.");
    }
  });

// Sign-Up Page
app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post("/sign-up", async (req, res, next) => {
  try {
    const { first_name, last_name, email, password, confirm_password } =
      req.body;

    if (password !== confirm_password) {
      return res.status(400).send("Passwords do not match!");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (first_name, last_name, email, password) VALUES ($1, $2, $3, $4) RETURNING *",
      [first_name, last_name, email, hashedPassword]
    );

    const newUser = result.rows[0];

    req.login(newUser, (err) => {
      if (err) return next(err);

      res.redirect("/join-club");
    });
  } catch (error) {
    console.error(error);
    next(error);
  }
});

// Join Club Page
app.get("/join-club", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }
  res.render("join-club");
});

app.post("/join-club", async (req, res) => {
  const { passcode } = req.body;

  const isMemberPasscode = await bcrypt.compare(
    passcode,
    process.env.MEMBER_PASSCODE_HASH
  );

  const isAdminPasscode = await bcrypt.compare(
    passcode,
    process.env.ADMIN_PASSCODE_HASH
  );

  if (isMemberPasscode) {
    await pool.query("UPDATE users SET is_member = true WHERE id = $1", [
      req.user.id,
    ]);
    res.redirect("/");
  } else if (isAdminPasscode) {
    await pool.query("UPDATE users SET is_admin = true WHERE id = $1", [
      req.user.id,
    ]);
    res.redirect("/");
  } else {
    res.status(400).send("Incorrect passcode.");
  }
});

// Login Page
app.get("/login", (req, res) => res.render("login-form"));

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureMessage: true,
  })
);

passport.use(
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const { rows } = await pool.query(
          "SELECT * FROM users WHERE email = $1",
          [email]
        );
        const user = rows[0];

        if (!user) {
          return done(null, false, { message: "Incorrect email" });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
          return done(null, false, { message: "Incorrect password" });
        }

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
      id,
    ]);
    const user = rows[0];

    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Render New Message Form
app.get("/new-message", (req, res) => {
    if (!req.isAuthenticated() || !req.user.is_member) {
      return res.redirect("/login");
    }
    res.render("new-message-form");
  });
  
  // Handle New Message Submission
  app.post("/new-message", async (req, res) => {
    if (!req.isAuthenticated() || !req.user.is_member) {
      return res.redirect("/login");
    }
  
    try {
      const { title, text } = req.body;
      await pool.query(
        "INSERT INTO messages (title, text, user_id) VALUES ($1, $2, $3)",
        [title, text, req.user.id]
      );
  
      res.redirect("/");
    } catch (error) {
      console.error(error);
      res.status(500).send("Error saving message.");
    }
  });

// Logout
app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.listen(3000, () => console.log("app listening on port 3000!"));

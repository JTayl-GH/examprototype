// Core Backend //

const express = require("express");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const session = require("express-session");
const path = require("path");

const app = express();
const dbPath = path.join(__dirname, 'database', 'db.sqlite');
console.log("DB Path:", dbPath);  // Check if path is correct

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error("Failed to open DB:", err.message);
    } else {
        console.log("Database opened successfully.");
    }
});

// Middleware 

app.use(express.json()); // parses requests - e.g. username = j & age = 25 TO req.body = { username: "j", age: 25}
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: "mykey", // secret session id cookie
    resave: false, // prevents session from being saved if it hasnt been modified.
    saveUninitialized: false // prevents empty sessions from being saved in database
}));

// Create Users table if not exists
db.run(`CREATE TABLE IF NOT EXISTS users ( 
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT
)`); // Backticks allow for multi-line statements which reduces long lines, cleaner code for later developers.

// Routes
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "./pages/home.html"))); //gets direct path of page, accesses page when request is sent and sends files to return full html interface.
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "./pages/login.html")));
app.get("/register", (req, res) => res.sendFile(path.join(__dirname, "./pages/register.html")));
app.get("/forgot-password", (req, res) => res.sendFile(path.join(__dirname, "./pages/forgot-password.html")));


// Register user

app.post("/register", async (req, res) => {
    // get email and password from form
    let email = req.body.email.toLowerCase(); // forces email body to be in lower case
    const password = req.body.password;
    const confirmPassword = req.body.confirmPassword;

    // server side validation of email format:
    if (!/^\S+@\S+\.\S+$/.test(email)) {  // !/^\S+@\S+\.\S+$/ tests email format (name@address.any)
        return res.status(400).send("Invalid email format.");
    }

    // Check if passwords match
    if (password !== confirmPassword) { // if passwords do not match, send user alert that they do not match.
        return res.status(200).send("Passwords do not match.");
    }

    // Hash password
    const hash = await bcrypt.hash(password, 10); // encrypts password with 10 random characters, await pauses function until encryption has been complete.

    // insert in database
    db.run(
        `INSERT INTO users (email, password) VALUES (?, ?)`, // SQL is case insensitive, used to make sql easier to detect and read.
        // VALUES describes the actual data being put into the columns and the ? are placeholders.
        [email, hash],
        (err) => {
            if (err) return res.send("User already exists.")
                res.redirect("/login"); // when successful, sends user to login
        }
    );
});

// Login User

app.post("/login", async (req, res) => {
    let email = req.body.email.toLowerCase();
    const password = req.body.password;

    // Validate email format:
    if (!/^\S+@\S+\.\S+$/.test(email)) {  // !/^\S+@\S+\.\S+$/ tests email format
        return res.status(400).send("Invalid email format.");
    }

    // Hardcoded test login
    if (email === "test@example.com") {
        if (password !== "password123") {
            return res.send("Invalid password.");
        }

        req.session.userId = 999; // important: not 0
        return res.redirect("/dashboard");
    }

    
    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (!user) return res.send("User not found."); // grabs username from database and validates if its inside the database or not to the user.

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.send("Invalid password."); // compares password to inputted data and listens to encrypted password using bcrypt and validates if the password is correcto or not.

        req.session.userId = user.id;
        res.redirect("/dashboard"); // redirects user to dashboard after session is connected to user account.
    });
});

// Auth check middleware

function auth(req, res, next) { // requests, responds and passes function
    if (!req.session.userId) { // requests userId, responds accordingly if it exists
        return res.redirect("/login") // redirects user to login page.
    }
    next();
}


// FORGOT PASSWORD

db.run(`ALTER TABLE users ADD COLUMN resetToken TEXT`, () => {});  // reset token is created
db.run(`ALTER TABLE users ADD COLUMN resetTokenExpiry INTEGER`, () => {}); // expiration window is made to prevent stolen account


app.get("/auth-status", (req, res) => {
    console.log("auth-status requested, session:", req.session);
    res.json({ loggedIn: !!req.session.userId });
});

// Dashboards Route

app.get("/dashboard", auth, (req, res) =>
    res.sendFile(path.join(__dirname, "./pages/dashboard.html"))
);

// Log out

app.get("/logout", (req, res) => {
    req.session.destroy(() => res.redirect("/")); // destroys session (user being logged in) entirely and redirects user to homepage.
});

// static file must go last
app.use(express.static("public"));

// Start Server

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
; // cd project, node server.js in terminal to run server
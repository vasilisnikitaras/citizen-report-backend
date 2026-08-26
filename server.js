const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

console.log("Loaded express");
console.log("Loaded cors");
console.log("Loaded pg");
console.log("Loaded bcrypt");
console.log("Loaded jwt");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

/* ============================
   AUTH MIDDLEWARE
============================ */
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) {
    return res.status(401).json({ error: "No token" });
  }

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

/* ============================
   REGISTER
============================ */
app.post("/register", async (req, res) => {
  const { fullName, email, community, password } = req.body;

  console.log("REGISTER REQUEST:", { fullName, email, community });

  const cleanFullName = fullName.trim();

  if (!cleanFullName || !email || !community || !password) {
    return res.status(400).json({ error: "Όλα τα πεδία είναι υποχρεωτικά" });
  }

  try {
    const check = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (check.rows.length > 0) {
      return res.status(400).json({ error: "Το email υπάρχει ήδη" });
    }

    const hashed = await bcrypt.hash(password, 10);

    await pool.query(
  `INSERT INTO users (email, created_at, role, username, password, community, fullname)
   VALUES ($1, NOW(), $2, $3, $4, $5, $6)`,
  [email, "user", cleanFullName, hashed, community, cleanFullName]
);

    console.log("REGISTER SUCCESS:", email);
    res.json({ success: true });

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/* ============================
   LOGIN
============================ */
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  console.log("LOGIN REQUEST RAW:", { username });

  // ⭐ FIX — κόβει τα κενά
  const cleanUsername = username.trim();

  console.log("LOGIN CLEAN:", cleanUsername);

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [cleanUsername]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "User not found" });
    }

    const user = result.rows[0];

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(400).json({ error: "Wrong password" });
    }

   const token = jwt.sign(
  {
    id: user.id,
    username: user.username,
    role: user.role,
    community: user.community
  },
  process.env.JWT_SECRET,
  { expiresIn: "24h" }
);


    console.log("LOGIN SUCCESS:", cleanUsername);
    res.json({ token });

  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ error: "DB error" });
  }
});
/* ============================
   REPORT (secure)
============================ */
app.post("/report", auth, async (req, res) => {
  const { type, description, location, timestamp } = req.body;
  const user = req.user.username;
  const community = req.user.community;   // ⭐ ΑΥΤΟ ΕΔΩ

  console.log("REPORT REQUEST:", { type, location, user, community });

  try {
    await pool.query(
      'INSERT INTO reports (type, description, location, timestamp, "user", community) VALUES ($1, $2, $3, $4, $5, $6)',
      [type, description, location, timestamp, user, community]   // ⭐ ΚΑΙ ΑΥΤΟ
    );

    console.log("REPORT SAVED");
    res.json({ success: true });

  } catch (err) {
    console.error("REPORT ERROR:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/* ============================
   GET REPORTS (FILTERED)
============================ */
app.get("/reports", auth, async (req, res) => {
  const { role, community, username } = req.user;

  try {
    let result;

    if (role === "admin") {
      // ⭐ Admin βλέπει ΜΟΝΟ τα reports της κοινότητάς του
      result = await pool.query(
        "SELECT * FROM reports WHERE community = $1 ORDER BY id DESC",
        [community]
      );
    } else {
      // ⭐ User βλέπει ΜΟΝΟ τα δικά του
      result = await pool.query(
        'SELECT * FROM reports WHERE "user" = $1 ORDER BY id DESC',
        [username]
      );
    }

    res.json(result.rows);

  } catch (err) {
    console.error("REPORT FETCH ERROR:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/* ============================
   CLEAR REPORTS (ADMIN ONLY)
============================ */
app.delete("/clear-reports", auth, async (req, res) => {
  try {
    await pool.query("DELETE FROM reports");
    res.json({ message: "All reports deleted" });
  } catch (err) {
    console.error("CLEAR REPORTS ERROR:", err);
    res.status(500).json({ error: "Failed to clear reports" });
  }
});


/* ============================
   START SERVER
============================ */
app.listen(3001, () => console.log("🔥 Server running on port 3001"));


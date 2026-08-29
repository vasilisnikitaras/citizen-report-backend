import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const { Pool } = pkg;

const app = express();

app.use(cors({
  origin: [
    "https://citizen-report-frontend.vercel.app",
    "https://citizen-report-frontend-main.vercel.app"
  ],
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

/* ============================
   REGISTER
============================ */
app.post("/register", async (req, res) => {
  const { fullName, email, username, community, password } = req.body;

  if (!fullName || !email || !username || !community || !password) {
    return res.status(400).json({ error: "Όλα τα πεδία είναι υποχρεωτικά" });
  }

  try {
    const checkEmail = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (checkEmail.rows.length > 0) {
      return res.status(400).json({ error: "Το email υπάρχει ήδη" });
    }

    const checkUser = await pool.query(
      "SELECT id FROM users WHERE username = $1",
      [username]
    );

    if (checkUser.rows.length > 0) {
      return res.status(400).json({ error: "Το username υπάρχει ήδη" });
    }

    const hashed = await bcrypt.hash(password, 10);

    await pool.query(
      `INSERT INTO users (email, created_at, role, username, password, community, fullname)
       VALUES ($1, NOW(), $2, $3, $4, $5, $6)`,
      [email, "user", username, hashed, community, fullName]
    );

    res.json({ success: true });

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/* ============================
   LOGIN (username + password)
============================ */
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  console.log("LOGIN REQUEST:", { username });

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (result.rows.length === 0) {
      console.log("USER NOT FOUND:", username);
      return res.status(400).json({ error: "User not found" });
    }

    const user = result.rows[0];

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      console.log("WRONG PASSWORD:", username);
      return res.status(400).json({ error: "Wrong password" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    console.log("LOGIN SUCCESS:", username);
    res.json({ token });

  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ error: "DB error" });
  }
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
   REPORT (secure)
============================ */
app.post("/report", auth, async (req, res) => {
  const { type, description, location, timestamp } = req.body;
  const username = req.user.username;

  try {
    // Βρες την κοινότητα του χρήστη
    const userData = await pool.query(
      "SELECT community FROM users WHERE username = $1",
      [username]
    );

    const community = userData.rows[0].community;

    await pool.query(
      `INSERT INTO reports (type, description, location, timestamp, "user", community)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [type, description, location, timestamp, username, community]
    );

    res.json({ success: true });

  } catch (err) {
    console.error("REPORT ERROR:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/* ============================
   GET REPORTS (admin + citizen filtering)
============================ */
app.get("/reports", auth, async (req, res) => {
  try {
    const username = req.user.username;

    const userResult = await pool.query(
      "SELECT role, community FROM users WHERE username = $1",
      [username]
    );

    const user = userResult.rows[0];

    let result;

    if (user.role === "admin") {
      result = await pool.query(
        'SELECT * FROM reports ORDER BY timestamp DESC'
      );
    } else {
      result = await pool.query(
        'SELECT * FROM reports WHERE community = $1 ORDER BY timestamp DESC',
        [user.community]
      );
    }

    res.json(result.rows);

  } catch (err) {
    console.error("GET REPORTS ERROR:", err);
    res.status(500).json({ error: "DB error" });
  }
});

/* ============================
   START SERVER
============================ */
export default app;

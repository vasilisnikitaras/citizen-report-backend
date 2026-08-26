// POST /register
router.post("/register", async (req, res) => {
  try {
    const { fullName, email, username, community, password } = req.body;

    // ⭐ TRIM FIX
    const cleanFullName = fullName.trim();

    // Validation
    if (!cleanFullName || !email || !username || !community || !password) {
      return res.status(400).json({ error: "Όλα τα πεδία είναι υποχρεωτικά" });
    }

    // Check if username exists
    const checkUser = await client.query(
      "SELECT id FROM users WHERE username = $1",
      [username]
    );

    if (checkUser.rows.length > 0) {
      return res.status(400).json({ error: "Το username υπάρχει ήδη" });
    }

    // Check if email exists
    const checkEmail = await client.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (checkEmail.rows.length > 0) {
      return res.status(400).json({ error: "Το email υπάρχει ήδη" });
    }

    // Hash password
    const hash = await bcrypt.hash(password, 10);

    // Insert user
    await client.query(
      `INSERT INTO users (username, email, password, role, community, fullName)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [username, email, hash, "user", community, cleanFullName]
    );

    return res.json({ success: true, message: "Ο χρήστης δημιουργήθηκε!" });

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

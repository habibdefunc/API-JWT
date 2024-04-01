const express = require("express");
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

const dbUrl = new URL(process.env.DATABASE_URL);

const pool = mysql.createPool({
  host: dbUrl.hostname,
  user: dbUrl.username,
  password: dbUrl.password,
  database: dbUrl.pathname.substr(1),
  port: dbUrl.port,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

function authenticateToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) {
    return res.sendStatus(401);
  }
  jwt.verify(
    token.replace("Bearer ", ""),
    process.env.JWT_SECRET,
    (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    }
  );
}

app.post("/register", async (req, res) => {
  const { username, password, email } = req.body;

  if (typeof username !== "string" || !username.trim()) {
    return res
      .status(400)
      .json({ message: "Username harus berupa teks dan tidak boleh kosong" });
  }

  if (typeof password !== "string" || !password.trim()) {
    return res
      .status(400)
      .json({ message: "Password harus berupa teks dan tidak boleh kosong" });
  }

  if (typeof email !== "string" || !email.trim()) {
    return res
      .status(400)
      .json({ message: "Email harus berupa teks dan tidak boleh kosong" });
  }

  try {
    const [rows, fields] = await pool.execute(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );

    if (rows.length > 0) {
      return res.status(400).json({ message: "Username sudah ada" });
    }
    await pool.execute(
      "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
      [username, password, email]
    );
    res.status(201).json({ message: "User terdaftar berhasil" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (typeof username !== "string" || !username.trim()) {
    return res
      .status(400)
      .json({ message: "Username harus berupa teks dan tidak boleh kosong" });
  }

  if (typeof password !== "string" || !password.trim()) {
    return res
      .status(400)
      .json({ message: "Password harus berupa teks dan tidak boleh kosong" });
  }

  try {
    const [rows, fields] = await pool.execute(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: "Username atau password salah" });
    }

    const user = rows[0];

    if (user.password !== password) {
      return res.status(401).json({ message: "Username atau password salah" });
    }

    const token = jwt.sign(
      { username: user.username },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );
    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/checklists", authenticateToken, async (req, res) => {
  try {
    const [rows, fields] = await pool.execute("SELECT * FROM checklist");
    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});
app.post("/checklists", authenticateToken, async (req, res) => {
  const { name } = req.body;
  if (typeof name !== "string" || !name.trim()) {
    return res
      .status(400)
      .json({ message: "Nama harus berupa teks dan tidak boleh kosong" });
  }

  try {
    await pool.execute("INSERT INTO checklist (name) VALUES (?)", [name]);
    res.status(201).json({ message: "Checklist created successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});
app.delete("/checklists/:id", authenticateToken, async (req, res) => {
  const id = req.params.id;
  try {
    const [result] = await pool.execute("DELETE FROM checklist WHERE id = ?", [
      id,
    ]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "checklistId tidak ditemukan" });
    }
    res.json({ message: `Checklist with ID ${id} deleted successfully` });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/checklists/:id/item", authenticateToken, async (req, res) => {
  const checklistId = req.params.id;
  try {
    const [checklists] = await pool.execute(
      "SELECT * FROM checklist WHERE id = ?",
      [checklistId]
    );
    if (checklists.length === 0) {
      return res.status(404).json({ message: "Checklist not found" });
    }

    const [items] = await pool.execute(
      "SELECT name FROM checklistitem WHERE cheklist_id = ?",
      [checklistId]
    );

    res.json(items);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});
app.get("/checklists/:id/item/:itemId", authenticateToken, async (req, res) => {
  const { id: checklistId, itemId } = req.params;
  try {
    const [checklist] = await pool.execute(
      "SELECT * FROM checklist WHERE id = ?",
      [checklistId]
    );

    if (checklist.length === 0) {
      return res.status(404).json({ message: "Checklist not found" });
    }

    const [item] = await pool.execute(
      "SELECT name FROM checklistitem WHERE cheklist_id = ? AND id = ?",
      [checklistId, itemId]
    );

    if (item.length === 0) {
      return res.status(404).json({ message: "Checklist item not found" });
    }

    res.json(item[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});
app.post("/checklists/:id/item", authenticateToken, async (req, res) => {
  const checklistId = req.params.id;
  const { name } = req.body;

  if (typeof name !== "string" || name.trim() === "") {
    return res
      .status(400)
      .json({ message: "Nama harus diisi dan berupa teks" });
  }

  try {
    const [checklists] = await pool.execute(
      "SELECT * FROM checklist WHERE id = ?",
      [checklistId]
    );

    if (checklists.length === 0) {
      return res.status(404).json({ message: "Checklist tidak ditemukan" });
    }

    await pool.execute(
      "INSERT INTO checklistitem (name, cheklist_id) VALUES (?, ?)",
      [name, checklistId]
    );

    res.status(201).json({ message: "Item checklist berhasil dibuat" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.put(
  "/checklists/:checklistId/item/:itemId",
  authenticateToken,
  async (req, res) => {
    const { checklistId, itemId } = req.params;
    const { name } = req.body;

    if (isNaN(checklistId) || isNaN(itemId)) {
      return res
        .status(400)
        .json({ message: "ChecklistId dan itemId harus berupa angka" });
    }

    if (typeof name !== "string" || name.trim() === "") {
      return res
        .status(400)
        .json({ message: "Nama harus diisi dan berupa teks" });
    }

    try {
      const [result] = await pool.execute(
        "UPDATE checklistitem SET name = ? WHERE id = ? AND cheklist_id = ?",
        [name, itemId, checklistId]
      );

      let status = false;
      if (result.affectedRows > 0) {
        status = true;
      }
      if (result.affectedRows === 0) {
        return res
          .status(404)
          .json({ message: "checklistId atau itemId tidak ditemukan" });
      }
      res.json({
        message: "Item checklist berhasil diperbarui",
        status: status,
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

app.delete(
  "/checklists/:checklistId/item/:itemId",
  authenticateToken,
  async (req, res) => {
    const { checklistId, itemId } = req.params;
    if (isNaN(checklistId) || isNaN(itemId)) {
      return res
        .status(400)
        .json({ message: "ChecklistId dan itemId harus berupa angka" });
    }
    try {
      const [result] = await pool.execute(
        "DELETE FROM checklistitem WHERE id = ? AND cheklist_id = ?",
        [itemId, checklistId]
      );
      if (result.affectedRows === 0) {
        return res
          .status(404)
          .json({ message: "checklistId atau itemId tidak ditemukan" });
      }
      res.json({ message: "Checklist item deleted successfully" });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

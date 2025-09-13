const express = require("express");
const pool = require("./db");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");


const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Hello World dari Express");
});


const secret = 'secret_code';



app.post("/register", async (req, res) => {
  const { username, password, email } = req.body;

  try {

    const existingUser = await pool.query(
      "select * FROM users WHERE username = $1",
      [username]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "Username sudah dipakai" });
    }

    const hashcode = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (username,password,email)VALUES ($1,$2,$3) RETURNING*",
      [username, hashcode, email]
    )


    console.log("hash nya:", hashcode)
    res.json({ message: "User berhasil register", user: result.rows[0] });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });

  }
});

//login
app.post("/login", async (req, res) => {
  const { username, password, email } = req.body;

  try {



    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "User tidak ditemukan" });
    }


    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password)


    if (!validPassword) {
      return res.status(400).json({ error: "Password salah" });
    }

    if (user.email !== email) {
      return res.status(400).json({ error: "emailnya salah inimah" });
    }


    const token = jwt.sign(
      { id: user.id, username: user.username },
      secret,
      { expiresIn: '1h' }
    );


    res.json({ message: "Login sukses", token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});




 app.get('/dashboard', (req, res) => {
   const authHeader = req.headers['authorization'];
   const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    res.status(401).json({ error: 'token tidak ada' });
  }
  jwt.verify(token, secret, (err, user) => {
    if (err) {
      res.status(403).json({ error: 'token tidak valid' });
    }
    res.json({
      message: `selamat datang kembali ${user.username} dihalaman anda,!`,
      user: user,
      status: "SUKSES"
    });
  });
});
app.listen(3000, () => {
  console.log("Server jalan di http://localhost:3000");
});

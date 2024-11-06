require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');const mysql = require('mysql2');

const app = express();
app.use(express.json());

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

db.connect((err) => {
    if (err) throw err;
    console.log("Database connected!");
});

app.post('/register', async (req, res) => {
    const { full_name, email, password, dob, gender } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const twoFactorSecret = speakeasy.generateSecret({ name: "Paycio" }); // Generates a secret for 2FA

        db.query(
            'INSERT INTO employee (full_name, email, password, date_of_birth, gender, two_factor_secret) VALUES (?, ?, ?, ?, ?, ?)',
            [full_name, email, hashedPassword, dob, gender, twoFactorSecret.base32],
            (err, result) => {
                if (err) return res.status(500).send("Database error: " + err);

                qrcode.toDataURL(twoFactorSecret.otpauth_url, (err, imageUrl) => {
                    if (err) return res.status(500).send("Error generating QR code");

                    res.status(201).json({
                        message: "User registered successfully.",
                        qrCodeUrl: imageUrl, 
                        twoFactorSecret: twoFactorSecret.base32, 
                    });
                });
            }
        );
    } catch (error) {
        res.status(500).send("Error in registration: " + error.message);
    }
});

app.post('/login', async (req, res) => {
    const { email, password, twoFactorCode } = req.body;

    try {
        db.query('SELECT * FROM employee WHERE email = ?', [email], async (err, result) => {
            if (err) return res.status(500).send("Database error: " + err);
            if (!result.length) return res.status(401).send("Invalid email or password.");

            const user = result[0];
            const passwordMatch = await bcrypt.compare(password, user.password);

            if (!passwordMatch) return res.status(401).send("Invalid email or password.");

            const verified = speakeasy.totp.verify({
                secret: user.two_factor_secret,
                encoding: 'base32',
                token: twoFactorCode,
            });

            if (!verified) return res.status(401).send("Invalid 2FA code.");

            const token = jwt.sign({ id: user.employee_id }, process.env.JWT_SECRET, { expiresIn: '1h' });

            res.status(200).json({
                message: "Login successful",
                token,
                user: {
                    employee_id: user.employee_id,
                    employee_name: user.full_name,
                    email: user.email,
                }
            });
        });
    } catch (error) {
        console.error("Error in /login:", error);
        res.status(500).send("An error occurred during login.");
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

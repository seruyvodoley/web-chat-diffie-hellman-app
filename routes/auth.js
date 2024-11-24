const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();

const router = express.Router();

// Временная "база данных" пользователей
let users = [];

// Регистрация нового пользователя
router.post('/register', async (req, res) => {
    const { username, password } = req.body;
    console.log('Register request body:', req.body);

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    const userExists = users.find(user => user.username === username);
    if (userExists) {
        return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { username, password: hashedPassword };
    users.push(newUser);

    res.status(201).json({ message: 'User registered successfully' });
});

// Вход пользователя
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log('Login request body:', req.body);

        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }

        const user = users.find(user => user.username === username);
        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        console.log('JWT_SECRET used for signing:', process.env.JWT_SECRET);
        const payload = { username: user.username };
        console.log('Payload for JWT:', payload);

        console.log('Attempting to sign token with payload:', payload);
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
        console.log('Generated token:', token);

        res.json({ message: 'Login successful', token });
    } catch (err) {
        console.error('Error generating token:', err.message);
        res.status(500).json({ message: 'Internal server error' });
    }
});

module.exports = router;

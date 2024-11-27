const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const pool = require('./db');
const cookieParser = require('cookie-parser'); // Подключаем cookie-parser

// Загрузка переменных окружения
dotenv.config();

// Подключение маршрутов авторизации
const authRouter = require('./routes/auth');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const userKeys = {}; // { username: sharedSecret }

app.use(express.json());
app.use(express.static('public'));
app.use(cookieParser()); // Добавляем middleware для обработки куков
app.use('/auth', authRouter); // Маршруты авторизации


io.on('connection', (socket) => {
    console.log('A new client connected');

    const p = 23; // Простое число
    const g = 5;  // Основа
    const privateKey = Math.floor(Math.random() * 20) + 1;
    const publicKey = Math.pow(g, privateKey) % p;

    // Отправляем параметры DH клиенту
    socket.emit('dh-params', { p, g, serverPublicKey: publicKey });

    let isAuthenticated = false;

    socket.on('dh-key-exchange', (clientPublicKey) => {
        if (socket.sharedSecret) {
            return;
        }
        const sharedSecret = Math.pow(clientPublicKey, privateKey) % p;
        socket.sharedSecret = sharedSecret;
        socket.emit('dh-complete');
    });

    socket.on('authenticate', (encryptedData) => {
        if (isAuthenticated) {
            return;
        }
        try {
            console.log('Encrypted data:', encryptedData);
            const decryptedData = decryptMessage(encryptedData, socket.sharedSecret);
            console.log('Decrypted data:', decryptedData); // Логируем расшифрованные данные
    
            const { username, password } = JSON.parse(decryptedData);
            console.log('Decrypted username:', username);
            console.log('Decrypted password:', password);
    
            pool.query('SELECT * FROM users WHERE username = $1', [username], async (err, result) => {
                if (err) {
                    console.error('Database error:', err);
                    socket.emit('auth-failure', { message: 'Authentication failed' });
                    return;
                }
    
                const user = result.rows[0];
                if (!user) {
                    console.log('User not found');
                    socket.emit('auth-failure', { message: 'Invalid username or password' });
                    return;
                }
    
                const passwordMatch = await bcrypt.compare(password, user.password_hash);
                console.log('Password match:', passwordMatch);
                if (!passwordMatch) {
                    socket.emit('auth-failure', { message: 'Invalid username or password' });
                    return;
                }
    
                isAuthenticated = true;
                const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
                socket.username = username;
                userKeys[username] = socket.sharedSecret;
                socket.emit('auth-success', { message: 'Authentication successful', token });
                io.emit('update-keys', { username, sharedSecret: socket.sharedSecret });
                // Дополнительные действия, например, обновление ключей
                socket.broadcast.emit('message', {
                    username: 'System',
                    message: `${socket.username} has joined the chat!`
                });
            });
        } catch (err) {
            console.error('Decryption error:', err);
            socket.emit('auth-failure', { message: 'Decryption failed' });
        }
    });

    // Обработка входящих сообщений
    socket.on('message', (encryptedMessage) => {
        if (!socket.username || !socket.sharedSecret) {
            console.error(`${socket.username} user attempted to send a message`);
            return;
        }

        io.emit('message', {
            username: socket.username,
            message: encryptedMessage,
        });
    });

    socket.on('disconnect', () => {
        if (socket.username) {
            console.log(`${socket.username} disconnected`);
            delete userKeys[socket.username];
            socket.broadcast.emit('message', {
                username: 'System',
                message: `${socket.username} has left the chat.`
            });
        }
    });
});

// Функция для дешифрования сообщения
function decryptMessage(encryptedMessage, sharedSecret) {
    return String.fromCharCode(...encryptedMessage.map(char => char ^ sharedSecret));
}

// Обработчик для извлечения токена из куки
function getTokenFromCookies(req) {
    const token = req.cookies.token;
    if (!token) {
        return null;  // Нет токена
    }
    return token;  // Возвращаем токен
}

// Обработка запроса на аутентификацию (например, на вход)
app.post('/auth/login', (req, res) => {
    const { encryptedData } = req.body;
    const token = getTokenFromCookies(req);  // Извлекаем токен из куки

    if (token) {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            return res.json({ message: 'Already authenticated', token });
        } catch (err) {
            return res.status(401).json({ message: 'Invalid token' });
        }
    } else {
        return res.status(401).json({ message: 'No token found' });
    }
});

const PORT = process.env.PORT || 3030;
server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

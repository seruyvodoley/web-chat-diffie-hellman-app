const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

// Загрузка переменных окружения
dotenv.config();

const authRouter = require('./routes/auth'); // Подключение маршрутов авторизации

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Middleware для обработки JSON и статических файлов
app.use(express.json());
app.use(express.static('public'));

// Content Security Policy
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src 'self'; font-src 'self' https://fonts.gstatic.com;");
    next();
});

// Подключение маршрутов авторизации
app.use('/auth', authRouter);

const authenticate = async (socket, next) => {
    try {
        const token = socket.handshake.query.token;
        console.log('Handshake query:', socket.handshake.query);

        if (!token || token === 'undefined') {
            console.error('Token is missing or undefined');
            throw new Error('Authentication token is missing');
        }

        console.log('Token received in WebSocket handshake:', token);
        console.log('JWT_SECRET used for verification:', process.env.JWT_SECRET);

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log('Decoded token:', decoded);

        socket.username = decoded.username;
        next();
    } catch (err) {
        console.error('Authentication error:', err.message);
        next(new Error('Authentication failed'));
    }
};

// WebSocket
io.use(authenticate).on('connection', (socket) => {
    console.log(`${socket.username} connected`);

    // Генерация пары ключей Диффи-Хеллмана
    const dh = crypto.createDiffieHellman(2048);
    const publicKey = dh.generateKeys();
    const privateKey = dh.getPrivateKey();

    socket.emit('dh-public-key', publicKey.toString('hex'));

    // Получаем публичный ключ клиента
    socket.on('dh-key-exchange', (clientPublicKeyHex) => {
        const clientPublicKey = Buffer.from(clientPublicKeyHex, 'hex');
        const sharedSecret = dh.computeSecret(clientPublicKey);

        socket.sharedSecret = sharedSecret;
        console.log(`${socket.username} established a secure connection`);
    });

    // Обработка зашифрованных сообщений
    socket.on('message', (encryptedMessage) => {
        const decipher = crypto.createDecipheriv('aes-256-cbc', socket.sharedSecret, Buffer.alloc(16, 0));
        let decryptedMessage = decipher.update(encryptedMessage, 'hex', 'utf-8');
        decryptedMessage += decipher.final('utf-8');

        console.log(`Received message from ${socket.username}: ${decryptedMessage}`);
        
        const cipher = crypto.createCipheriv('aes-256-cbc', socket.sharedSecret, Buffer.alloc(16, 0));
        let encryptedResponse = cipher.update('Message received', 'utf-8', 'hex');
        encryptedResponse += cipher.final('hex');

        socket.emit('message', encryptedResponse);
    });

    socket.on('disconnect', () => {
        console.log(`${socket.username} disconnected`);
    });
});

// Запуск сервера
const PORT = process.env.PORT || 3030;
server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
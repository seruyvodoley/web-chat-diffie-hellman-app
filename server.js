const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const userKeys = {}; // { username: sharedSecret }
dotenv.config();

const authRouter = require('./routes/auth'); // Подключение маршрутов авторизации

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Middleware для обработки JSON и статических файлов
app.use(express.json());
app.use(express.static('public'));

// Подключение маршрутов авторизации
app.use('/auth', authRouter);

// Простая функция для возведения в степень с модулем
function modPow(base, exponent, mod) {
    let result = 1;
    base = base % mod;
    while (exponent > 0) {
        if (exponent % 2 === 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exponent = Math.floor(exponent / 2);
    }
    return result;
}

// WebSocket
io.on('connection', (socket) => {
    console.log('A user connected');

    // Генерация DH параметров
    const p = 23; // Простое число
    const g = 5;  // Основа
    const privateKey = Math.floor(Math.random() * 20) + 1;
    const publicKey = Math.pow(g, privateKey) % p;

    // Отправляем параметры DH клиенту
    socket.emit('dh-params', { p, g, serverPublicKey: publicKey });

    // Сохранение информации о новом ключе после DH-обмена
    socket.on('dh-key-exchange', (clientPublicKey) => {
        const sharedSecret = Math.pow(clientPublicKey, privateKey) % p;
        socket.sharedSecret = sharedSecret;
        console.log(`Shared secret established: ${sharedSecret}`);

        // Отправляем обновленный список ключей текущему пользователю
        // Даем возможность аутентифицироваться, но после DH-обмена
    });

    // Middleware для аутентификации WebSocket
    const authenticate = async (socket, next) => {
        try {
            const token = socket.handshake.query.token;
            if (!token) {
                throw new Error('Authentication token is missing');
            }

            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            socket.username = decoded.username;
            next();
        } catch (err) {
            next(new Error('Authentication failed'));
        }
    };

    // Middleware для аутентификации WebSocket
    io.use(authenticate);

    socket.on('disconnect', () => {
        console.log('A user disconnected');
    });
});

// Запуск сервера
const PORT = process.env.PORT || 3030;
server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

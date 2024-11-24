const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const userKeys = {}; // { username: sharedSecret }
// Загрузка переменных окружения
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

// WebSocket
io.use(authenticate).on('connection', (socket) => {
    console.log(`${socket.username} connected`);

    // Отправка всех текущих ключей новому пользователю
    socket.emit('all-keys', userKeys);

    // Генерация DH параметров
    const p = 23; // Простое число
    const g = 5;  // Основа
    const privateKey = Math.floor(Math.random() * 20) + 1;
    const publicKey = Math.pow(g, privateKey) % p;

    socket.emit('dh-params', { p, g, serverPublicKey: publicKey });

    // Сохранение информации о новом ключе после DH-обмена
    socket.on('dh-key-exchange', (clientPublicKey) => {
        const sharedSecret = Math.pow(clientPublicKey, privateKey) % p;
        socket.sharedSecret = sharedSecret;
    
        userKeys[socket.username] = sharedSecret; // Сохраняем ключ для пользователя
        console.log(`${socket.username} shared secret established: ${sharedSecret}`);
    
        // Отправляем обновленный список ключей текущему пользователю
        socket.emit('all-keys', userKeys);
    
        // Уведомление остальных пользователей
        socket.broadcast.emit('update-keys', { username: socket.username, sharedSecret });
    });
    // Сообщение всем пользователям о подключении нового пользователя
    socket.broadcast.emit('message', {
        username: 'System',
        message: `${socket.username} has joined the chat!`
    });

    // Удаление ключа при отключении пользователя
    socket.on('disconnect', () => {
        console.log(`${socket.username} disconnected`);
        delete userKeys[socket.username];
        socket.broadcast.emit('remove-key', socket.username); // Уведомить остальных

        // Сообщение всем пользователям о выходе пользователя
        socket.broadcast.emit('message', {
            username: 'System',
            message: `${socket.username} has left the chat.`
        });
    });




    // Обработка сообщений
    socket.on('message', (encryptedMessage) => {
        try {
            console.log(`Server ${socket.username} says: ${encryptedMessage}`);
            io.emit('message', {
                username: socket.username, // Имя отправителя
                message: encryptedMessage, // Зашифрованное сообщение
            });
        } catch (err) {
            console.error('Error processing message:', err);
        }
    });
    

    
});

    


// Запуск сервера
const PORT = process.env.PORT || 3030;
server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

const express = require('express');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const pool = require('./db');
const cookieParser = require('cookie-parser'); // Подключаем cookie-parser
const fs = require('fs');
const https = require('https');
const crypto = require('crypto'); // Для безопасной генерации больших чиселс
// Загрузка SSL-сертификатов
const sslOptions = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.cert'),
};

// Загрузка переменных окружения
dotenv.config();

// Подключение маршрутов авторизации
const authRouter = require('./routes/auth');

const app = express();
const httpsServer = https.createServer(sslOptions, app);
const io = new Server(httpsServer);

const userKeys = {}; // { username: sharedSecret }

app.use(express.json());
app.use(express.static('public'));
app.use(cookieParser()); // Добавляем middleware для обработки куков
app.use('/auth', authRouter); // Маршруты авторизации


io.on('connection', (socket) => {
    console.log(`New client connected: ${socket.id}`);
    if (userKeys[socket.username]) {
        console.log(`Duplicate connection detected for user: ${socket.username}`);
        socket.disconnect();
        return;
    }

    socket.emit('all-keys', userKeys); 

    const generateBigPrime = (length) => {
        while (true) {
            const primeCandidate = crypto.randomInt(10 ** (length - 1), 10 ** length);
            if (isPrime(primeCandidate)) return primeCandidate;
        }
    };

    const isPrime = (num) => {
        if (num <= 1) return false;
        if (num <= 3) return true;
        if (num % 2 === 0 || num % 3 === 0) return false;
        for (let i = 5; i * i <= num; i += 6) {
            if (num % i === 0 || num % (i + 2) === 0) return false;
        }
        return true;
    };

    const p = generateBigPrime(10); // Простое 50-значное число
    const g = crypto.randomInt(2, p - 1); // Генератор меньше `p`
    const privateKey = crypto.randomInt(10 ** 5, 10 ** 6); // Приватный ключ
    const publicKey = BigInt(g) ** BigInt(privateKey) % BigInt(p); // Открытый ключ
    // Отправляем параметры DH клиенту
    socket.emit('dh-params', { p, g, serverPublicKey: publicKey.toString() });

    let isAuthenticated = false;

    socket.on('dh-key-exchange', (clientPublicKey) => {
        if (socket.sharedSecret) {
            return;
        }
        const sharedSecret = BigInt(clientPublicKey) ** BigInt(privateKey) % BigInt(p);
        socket.sharedSecret = sharedSecret.toString(); // Общий секрет в строке
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
                //const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
                socket.username = username;
                userKeys[username] = socket.sharedSecret;
                socket.emit('auth-success', { message: 'Authentication successful' });
                io.emit('update-keys', { username, sharedSecret: socket.sharedSecret });
                const messageId = Math.random().toString(36).substring(2);
                // Дополнительные действия, например, обновление ключей
                io.emit('message', {
                    username: 'System',
                    message: `${socket.username} has joined the chat!`,
                    messageId  // Добавляем уникальный ID
                });
            });
        } catch (err) {
            console.error('Decryption error:', err);
            socket.emit('auth-failure', { message: 'Decryption failed' });
        }
    });

    // Обработка входящих сообщений
    socket.on('message', (encryptedMessage) => {
        const messageId = Math.random().toString(36).substring(2);
        console.log(`Message received from ${socket.id}:`, encryptedMessage);
        console.log('Received message from:', socket.username);
    
        // Отправляем всем кроме отправителя
        socket.broadcast.emit('message', {
            username: socket.username,
            message: encryptedMessage,
            messageId,  // Добавляем уникальный ID
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


function getTokenFromCookies(req) {
    const token = req.cookies.token;
    if (!token) {
        console.error('Token not found in cookies');
        return null;
    }
    return token;
}

const PORT = process.env.PORT || 3030;
httpsServer.listen(PORT, () => {
    console.log(`Secure server running on https://localhost:${PORT}`);
});
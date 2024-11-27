let socket;
const userKeys = {}; // { username: sharedSecret }

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

function connectToChat() {
    io.on('connection', (socket) => {
        console.log('A new client connected');
        socket.emit('all-keys', userKeys); 
    
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
            console.log('Received message from:', socket.username);
        
            // Отправляем всем кроме отправителя
            socket.broadcast.emit('message', {
                username: socket.username,
                message: encryptedMessage,
            });
        });

        // Получение всех ключей при подключении
        socket.on('all-keys', (keys) => {
            Object.assign(userKeys, keys); // Добавляем все существующие ключи
            console.log('All keys received:', userKeys);
        });

        socket.on('update-keys', ({ username, sharedSecret }) => {
            userKeys[username] = sharedSecret;
        });

        socket.on('remove-key', (username) => {
            delete userKeys[username];
            console.log(`Key removed for user ${username}`);
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
}
    

function encryptMessage(data) {
    const message = JSON.stringify(data);
    return Array.from(message).map((char) => char.charCodeAt(0) ^ socket.sharedSecret);
}

function login(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    })
        .then(response => response.json())
        .then(data => {
            if (data.token) {
                document.cookie = `token=${data.token};path=/;secure;samesite=strict`;
                console.log('Token saved in cookie:', data.token);
                alert('Login successful!');
                connectToChat();
            } else {
                console.error('Login failed:', data.message);
                alert('Login failed! Incorrect username or password');
            }
        })
        .catch(err => console.error('Login error:', err));
}

function register(event) {
    event.preventDefault();

    const username = document.getElementById('reg-username').value;
    const password = document.getElementById('reg-password').value;

    fetch('/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    })
        .then(response => response.json())
        .then(data => {
            if (data.message === 'User registered successfully') {
                alert('Registration successful! You can now log in.');
                showLoginForm();
            } else {
                alert('Registration failed: ' + data.message);
            }
        })
        .catch(err => {
            alert('Error: ' + err.message);
        });
}

document.addEventListener('DOMContentLoaded', () => {
    const token = getCookie('token');

    if (token) {
        console.log('Token found in cookie, connecting to chat...');
        connectToChat();
    }
});

function sendMessage() {
    const message = document.getElementById('message-input').value;
    if (!message.trim()) return;

    const encryptedMessage = Array.from(message).map(
        (char) => char.charCodeAt(0) ^ socket.sharedSecret
    );

    socket.emit('message', encryptedMessage);
    document.getElementById('message-input').value = '';
}

function checkEnter(event) {
    if (event.key === 'Enter') {
        sendMessage();
    }
}

function logout() {
    document.cookie = "token=;path=/;expires=Thu, 01 Jan 1970 00:00:00 UTC;secure;samesite=strict";
    socket?.disconnect();
    socket = null;
    document.getElementById('chat').style.display = 'none';
    document.getElementById('login-form').style.display = 'block';
}

function getCookie(name) {
    const cookies = document.cookie.split('; ');
    const cookie = cookies.find((row) => row.startsWith(`${name}=`));
    return cookie ? cookie.split('=')[1] : null;
}

function showRegisterForm() {
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('register-form').style.display = 'block';
}

function showLoginForm() {
    document.getElementById('register-form').style.display = 'none';
    document.getElementById('login-form').style.display = 'block';
}

window.showRegisterForm = showRegisterForm;
window.showLoginForm = showLoginForm;

window.sendMessage = sendMessage;
window.checkEnter = checkEnter;
window.logout = logout;

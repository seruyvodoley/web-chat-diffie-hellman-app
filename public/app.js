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
    const token = localStorage.getItem('token'); // Получение токена из localStorage
    if (!token) {
        console.error('No token found for WebSocket connection');
        return;
    }

    console.log('Connecting WebSocket with token:', token);
    socket = io('http://localhost:3030', { query: { token } });

    socket.on('connect', () => {
        console.log('Connected to the server');
        // Отображаем чат, только если WebSocket-соединение успешно
        document.getElementById('chat').style.display = 'block';
        document.getElementById('login-form').style.display = 'none';
    
        // Получаем параметры p, g и публичный ключ сервера
        socket.on('dh-params', ({ p, g, serverPublicKey }) => {
            console.log(`Received DH params from server: p=${p}, g=${g}, serverPublicKey=${serverPublicKey}`);
    
            const privateKey = Math.floor(Math.random() * 20) + 1; // Приватный ключ клиента
            const publicKey = Math.pow(g, privateKey) % p; // Публичный ключ клиента
            console.log(`Generated client keys: privateKey=${privateKey}, publicKey=${publicKey}`);
            const sharedSecret = Math.pow(serverPublicKey, privateKey) % p;

            

            userKeys[socket.username] = sharedSecret; // Сохраняем ключ
            socket.sharedSecret = sharedSecret;
            console.log(`Client shared secret: ${socket.sharedSecret}`);
            console.log(`Shared secret established: ${sharedSecret}`);
    
            // Отправка публичного ключа серверу
            socket.emit('dh-key-exchange', publicKey);
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
        
    });
    
    document.getElementById('chat').style.display = 'none';
    document.getElementById('login-form').style.display = 'block';
    // Обработка входящего сообщения
    socket.on('message', (data) => {
        const { username, message } = data;
    
        // Если сообщение от системы (например, пользователь подключился или отключился)
        if (username === 'System') {
            const formattedMessage = `[System] ${message}`;
            console.log(`System message: ${formattedMessage}`);
    
            const messageContainer = document.getElementById('messages');
            const messageElement = document.createElement('div');
            messageElement.textContent = formattedMessage;
            messageContainer.appendChild(messageElement);
        } else {
            // Используем ключ отправителя для расшифровки
            const senderKey = userKeys[username];
            if (!senderKey) {
                console.error(`No shared secret found for user: ${username}`);
                return;
            }
    
            const decryptedMessage = String.fromCharCode(
                ...message.map((char) => char ^ senderKey)
            );
    
            const formattedMessage = `${username} says: ${decryptedMessage}`;
            console.log(`Decrypted message: ${decryptedMessage}`);
    
            const messageContainer = document.getElementById('messages');
            const messageElement = document.createElement('div');
            messageElement.textContent = formattedMessage;
            messageContainer.appendChild(messageElement);
        }
    });
    
    
    
    
    
    
}   socket.on('disconnect', () => {
        console.log('WebSocket disconnected');
        document.getElementById('chat').style.display = 'none';
        document.getElementById('login-form').style.display = 'block';
    });


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
                localStorage.setItem('token', data.token);
                console.log('Token saved:', data.token);

                // Подключение WebSocket
                connectToChat();
            } else {
                console.error('Login failed:', data.message);
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
                showLoginForm(); // Показать форму логина
            } else {
                alert('Registration failed: ' + data.message);
            }
        })
        .catch(err => {
            alert('Error: ' + err.message);
        });
}

// Подключение при загрузке страницы, если токен есть
document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('token');
    if (token) {
        console.log('Token found in localStorage, connecting to chat...');
        connectToChat();
    }
});

// Обработка сообщений чата
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
    localStorage.removeItem('token');
    socket?.disconnect();
    socket = null;
    document.getElementById('chat').style.display = 'none';
    document.getElementById('login-form').style.display = 'block';
}
function showRegisterForm() {
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('register-form').style.display = 'block';
}

function showLoginForm() {
    document.getElementById('register-form').style.display = 'none';
    document.getElementById('login-form').style.display = 'block';
}

// Экспортируем функции в глобальную область
window.showRegisterForm = showRegisterForm;
window.showLoginForm = showLoginForm;

window.sendMessage = sendMessage;
window.checkEnter = checkEnter;
window.logout = logout;



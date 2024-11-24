let socket;

function connectToChat() {
    const token = localStorage.getItem('token'); // Получение токена из localStorage
    if (!token) {
        console.error('No token found for WebSocket connection');
        return;
    }

    console.log('Connecting WebSocket with token:', token);
    socket = io('http://localhost:3030', { query: { token } });

    socket.on('connect', () => {
        console.log('Successfully connected to the chat');
        document.getElementById('chat').style.display = 'block';
        document.getElementById('login-form').style.display = 'none';
    });

    socket.on('connect_error', (err) => {
        console.error('Connection error:', err.message);
    });

    socket.on('disconnect', () => {
        console.log('WebSocket disconnected');
        document.getElementById('chat').style.display = 'none';
        document.getElementById('login-form').style.display = 'block';
    });

    // Обработка сообщений от сервера
    socket.on('message', (encryptedMessage) => {
        const decipher = crypto.createDecipheriv('aes-256-cbc', socket.sharedSecret, Buffer.alloc(16, 0));
        let decryptedMessage = decipher.update(encryptedMessage, 'hex', 'utf-8');
        decryptedMessage += decipher.final('utf-8');
        console.log('Received message:', decryptedMessage);
    });
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

    try {
        const cipher = crypto.createCipheriv('aes-256-cbc', socket.sharedSecret, Buffer.alloc(16, 0));
        let encryptedMessage = cipher.update(message, 'utf-8', 'hex');
        encryptedMessage += cipher.final('hex');

        socket.emit('message', encryptedMessage);
        document.getElementById('message-input').value = '';
    } catch (err) {
        console.error('Error encrypting message:', err);
    }
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



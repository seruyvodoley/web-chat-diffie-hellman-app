let socket;
let userKeys = {}; // { username: sharedSecret }
let sharedSecret = null;

function connectToChat() {
    socket = io('http://localhost:3030');

    socket.on('connect', () => {
        console.log('Connected to the server');

        // Получаем параметры p, g и публичный ключ сервера
        socket.on('dh-params', ({ p, g, serverPublicKey }) => {
            console.log(`Received DH params from server: p=${p}, g=${g}, serverPublicKey=${serverPublicKey}`);

            const privateKey = Math.floor(Math.random() * 20) + 1; // Приватный ключ клиента
            const publicKey = Math.pow(g, privateKey) % p; // Публичный ключ клиента
            console.log(`Generated client keys: privateKey=${privateKey}, publicKey=${publicKey}`);

            // Вычисляем общий секрет
            sharedSecret = Math.pow(serverPublicKey, privateKey) % p;
            console.log(`Shared secret established: ${sharedSecret}`);

            // Отправляем публичный ключ серверу для завершения DH-обмена
            socket.emit('dh-key-exchange', publicKey);
        });

        // Далее, когда DH обмен завершен, аутентификация
        socket.on('dh-key-exchange', () => {
            // После обмена DH-ключами можно пройти аутентификацию
            // Запрашиваем токен пользователя
            const token = localStorage.getItem('token');
            if (!token) {
                console.error('No token found for WebSocket connection');
                return;
            }

            // Отправляем запрос на аутентификацию с токеном
            socket.emit('authenticate', { token });
        });

    });

    socket.on('disconnect', () => {
        console.log('WebSocket disconnected');
    });
}   
    
    
    
    
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
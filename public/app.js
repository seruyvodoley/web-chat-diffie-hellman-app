
let socket;
const userKeys = {}; // { username: sharedSecret }
let lastMessage = null;
let receivedMessageIds = new Set();

function setupSocketListeners() {
    if (socket.listeners('message').length > 0) {
        console.log('Listeners already set up');
        return;
    }

    socket.on('message', (data) => {
        console.log('Socket ID:', socket.id);

        const { messageId, username, message } = data;
        console.log('Message from server:', data);
    
        if (receivedMessageIds.has(messageId)) {
            console.log('Duplicate message received, ignoring');
            return;
        }
    
        receivedMessageIds.add(messageId);
    
        lastMessage = message;

        if (username === 'System') {
            const formattedMessage = `[System] ${message}`;
            console.log(`System message: ${formattedMessage}`);

            const messageContainer = document.getElementById('messages');
            const messageElement = document.createElement('div');
            messageElement.textContent = formattedMessage;
            messageContainer.appendChild(messageElement);
        } else {
            const senderKey = userKeys[username];
            console.log('Current userKeys:', userKeys);

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

    console.log('Socket listeners set up');
}


function connectToChat() {
    console.log('now working connect to chat');
    socket = io('https://localhost:3030', { secure: true });

    socket.on('connect', () => {
        console.log('Connected to server');

        socket.on('dh-params', ({ p, g, serverPublicKey }) => {
            console.log(`DH parameters received from server P: ${p}, g: ${g}, serverPublicKey: ${serverPublicKey}`);
            function generateRandomInt(min, max) {
                const range = max - min;
                const randomValue = crypto.getRandomValues(new Uint32Array(1))[0];  // Используем Web Crypto API
                return min + (randomValue % range);
            }
            const privateKey = generateRandomInt(10 ** 5, 10 ** 6);
            const publicKey = BigInt(g) ** BigInt(privateKey) % BigInt(p); // Открытый ключ
            const sharedSecret = BigInt(serverPublicKey) ** BigInt(privateKey) % BigInt(p); // Общий секрет

            socket.sharedSecret = sharedSecret.toString(); // Сохраняем общий секрет
            socket.emit('dh-key-exchange', publicKey.toString());
        });

        socket.on('dh-complete', () => {
            const username = document.getElementById('username')?.value || '';
            const password = document.getElementById('password')?.value || '';

            const token = getCookie('token');

            console.log('Username:', username);
            console.log('Password:', password);

            if (token) {
                socket.emit('authenticate', encryptMessage({ username, password }));
            } else {
                console.error('Token not found. Cannot authenticate.');
            }
            console.log('now finished dh');
        });

        socket.on('auth-success', (data) => {
            console.log('Authentication successful:', data);
            document.getElementById('login-form').style.display = 'none';
            document.getElementById('chat').style.display = 'block';
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

    setupSocketListeners();
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
                document.cookie = `token=${data.token};path=/;secure;samesite=strict;HttpOnly`;

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

    console.log(`Sending message: ${message}`);
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
    //document.cookie = "token=;path=/;expires=Thu, 01 Jan 1970 00:00:00 UTC;secure;samesite=strict";
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

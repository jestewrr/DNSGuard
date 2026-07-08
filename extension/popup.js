// ──────────────────────────────────────────────
// Utilities
// ──────────────────────────────────────────────

async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function showError(message, type = 'error-credentials') {
    const el = document.getElementById('login-error');
    el.textContent = message;
    el.className = type;
    el.style.display = 'block';
}

function clearError() {
    const el = document.getElementById('login-error');
    el.style.display = 'none';
    el.textContent = '';
}

function setLoginLoading(loading) {
    const btn = document.getElementById('login-btn');
    const spinner = document.getElementById('login-spinner');
    const btnText = document.getElementById('login-btn-text');
    btn.disabled = loading;
    spinner.style.display = loading ? 'block' : 'none';
    btnText.textContent = loading ? 'Signing in…' : 'Sign In';
}

// ──────────────────────────────────────────────
// Init
// ──────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function () {
    // Password show/hide toggle
    document.getElementById('pw-toggle-btn').addEventListener('click', function () {
        const pwInput = document.getElementById('password');
        const eyeShow = document.getElementById('eye-show');
        const eyeHide = document.getElementById('eye-hide');
        if (pwInput.type === 'password') {
            pwInput.type = 'text';
            eyeShow.style.display = 'none';
            eyeHide.style.display = 'block';
        } else {
            pwInput.type = 'password';
            eyeShow.style.display = 'block';
            eyeHide.style.display = 'none';
        }
    });

    // Auto-detect backend from active tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (tabs && tabs[0] && tabs[0].url) {
            const tabUrl = tabs[0].url;
            if (tabUrl.includes('localhost:5000') || tabUrl.includes('127.0.0.1:5000')) {
                chrome.storage.local.set({ backend_url: 'http://127.0.0.1:5000' }, updateUIFromStorage);
            } else if (tabUrl.includes('dnsguard-backend.onrender.com')) {
                chrome.storage.local.set({ backend_url: 'https://dnsguard-backend.onrender.com' }, updateUIFromStorage);
            } else {
                updateUIFromStorage();
            }
        } else {
            updateUIFromStorage();
        }
    });

    // React to storage changes (triggered by content.js sync_session)
    chrome.storage.onChanged.addListener(function (changes) {
        if (changes.user_id || changes.username) {
            updateUIFromStorage();
        }
    });

    document.getElementById('login-btn').addEventListener('click', handleLogin);
    document.getElementById('logout-btn').addEventListener('click', handleLogout);
    document.getElementById('register-btn').addEventListener('click', function () {
        chrome.storage.local.get(['backend_url'], function (result) {
            const currentBackend = result.backend_url || "https://dnsguard-backend.onrender.com";
            window.open(`${currentBackend}/register`, '_blank');
        });
    });
});

// ──────────────────────────────────────────────
// Session state
// ──────────────────────────────────────────────

function updateUIFromStorage() {
    chrome.storage.local.get(['user_id', 'username', 'backend_url'], function (result) {
        const userId = result.user_id;
        const username = result.username;
        const currentBackend = result.backend_url || 'https://dnsguard-backend.onrender.com';

        if (userId) {
            // Verify the session is still active — cookies sent automatically with credentials:'include'
            fetch(`${currentBackend}/api/session_status`, { credentials: 'include' })
                .then(r => r.json())
                .then(data => {
                    if (data.authenticated) {
                        showStatusSection(data.username || username);
                        checkCurrentTab(data.user_id || data.id || userId, currentBackend);
                    } else {
                        forceLocalLogout();
                    }
                })
                .catch(() => {
                    // Network error — show cached state so offline users aren't kicked out
                    showStatusSection(username);
                    checkCurrentTab(userId, currentBackend);
                });
        } else {
            showLoginSection();
        }
    });
}

// ──────────────────────────────────────────────
// Login
// ──────────────────────────────────────────────

async function handleLogin() {
    const user = document.getElementById('username').value.trim();
    const pass = document.getElementById('password').value;
    clearError();

    if (!user || !pass) {
        showError('Please fill in all fields.', 'error-credentials');
        return;
    }

    setLoginLoading(true);

    chrome.storage.local.get(['backend_url'], async function (result) {
        const currentBackend = result.backend_url || 'https://dnsguard-backend.onrender.com';

        try {
            // SHA-256 hash the password before sending — matches the web login form behaviour.
            // The backend stores werkzeug_hash(sha256(rawpassword)) and verifies the same way.
            const hashedPassword = await sha256(pass);

            const response = await fetch(`${currentBackend}/api/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',  // stores the HttpOnly dnsguard_token cookie
                body: JSON.stringify({ username: user, password: hashedPassword })
            });

            let data;
            try {
                data = await response.json();
            } catch {
                setLoginLoading(false);
                showError('Server returned an unexpected response.', 'error-server');
                return;
            }

            setLoginLoading(false);

            if (response.ok && data.success) {
                // Store only non-sensitive identifiers
                chrome.storage.local.set({
                    user_id: data.user_id || data.id,
                    username: data.username,
                    role: data.role,
                    backend_url: currentBackend
                }, function () {
                    clearError();
                    showStatusSection(data.username);
                    checkCurrentTab(data.user_id || data.id, currentBackend);
                });
            } else if (response.status === 401) {
                showError('Invalid username or password.', 'error-credentials');
            } else if (response.status >= 500) {
                showError('Server error. Please try again later.', 'error-server');
            } else {
                showError(data.error || 'Login failed. Please try again.', 'error-credentials');
            }
        } catch (e) {
            setLoginLoading(false);
            if (e instanceof TypeError && e.message.includes('fetch')) {
                showError('Cannot reach server. Check your connection.', 'error-network');
            } else {
                showError('An unexpected error occurred.', 'error-server');
            }
        }
    });
}

// ──────────────────────────────────────────────
// Logout
// ──────────────────────────────────────────────

function handleLogout() {
    chrome.storage.local.get(['backend_url'], function (result) {
        const currentBackend = result.backend_url || 'https://dnsguard-backend.onrender.com';
        fetch(`${currentBackend}/api/logout`, {
            method: 'POST',
            credentials: 'include'
        }).finally(() => {
            chrome.storage.local.remove(['user_id', 'username', 'role'], showLoginSection);
        });
    });
}

function forceLocalLogout() {
    chrome.storage.local.remove(['user_id', 'username', 'role'], showLoginSection);
}

// ──────────────────────────────────────────────
// UI Sections
// ──────────────────────────────────────────────

function showLoginSection() {
    document.getElementById('login-section').style.display = 'block';
    document.getElementById('status-section').style.display = 'none';
    clearError();
    setLoginLoading(false);
}

function showStatusSection(username) {
    document.getElementById('login-section').style.display = 'none';
    document.getElementById('status-section').style.display = 'block';
    document.getElementById('display-user').innerText = username || '';
    document.getElementById('user-info').style.display = 'block';
}

// ──────────────────────────────────────────────
// URL Check
// ──────────────────────────────────────────────

function checkCurrentTab(userId, currentBackend) {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (!tabs || tabs.length === 0) return;
        const currentUrl = tabs[0].url;

        if (!currentUrl || currentUrl.startsWith('chrome://') || currentUrl.startsWith('chrome-extension://')) {
            updateStatus('N/A', 'unknown');
            return;
        }

        fetch(`${currentBackend}/api/check_url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ url: currentUrl, user_id: userId })
        })
            .then(r => r.json())
            .then(data => {
                const colorMap = { Safe: 'safe', Suspicious: 'suspicious', Malicious: 'malicious' };
                updateStatus(data.status || 'Unknown', colorMap[data.status] || 'unknown');
            })
            .catch(() => updateStatus('Offline', 'unknown'));
    });
}

function updateStatus(text, className) {
    const el = document.getElementById('site-status');
    if (el) {
        el.innerText = text;
        el.className = className;
    }
}

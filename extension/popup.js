// The default URL of our Flask backend
let backendUrl = "https://dnsguard.onrender.com";

function setAuthenticatedState(username, currentBackend, userId, authToken) {
    chrome.storage.local.set({
        user_id: userId,
        username: username,
        auth_token: authToken,
        backend_url: currentBackend
    });

    document.getElementById('unauth-section').style.display = 'none';
    document.getElementById('auth-section').style.display = 'block';
    document.getElementById('display-user').innerText = username;
    checkCurrentTab(userId, currentBackend, authToken);
}

function setUnauthenticatedState() {
    chrome.storage.local.remove(['user_id', 'username', 'role', 'auth_token']);
    document.getElementById('auth-section').style.display = 'none';
    document.getElementById('unauth-section').style.display = 'block';
}

function updateUI() {
    chrome.storage.local.get(['backend_url', 'user_id', 'username', 'auth_token'], function (result) {
        const currentBackend = result.backend_url || backendUrl;
        const authToken = result.auth_token || null;

        document.getElementById('dashboard-link').href = `${currentBackend}/`;

        if (!authToken) {
            setUnauthenticatedState();
            return;
        }

        const headers = { 'Authorization': `Bearer ${authToken}` };
        fetch(`${currentBackend}/api/session_status`, { headers })
            .then(res => res.json())
            .then(data => {
                if (data.authenticated) {
                    setAuthenticatedState(
                        data.username,
                        currentBackend,
                        data.user_id || data.id,
                        data.auth_token || authToken
                    );
                } else {
                    setUnauthenticatedState();
                }
            })
            .catch(err => {
                console.error("Session verification failed:", err);
                if (result.username && result.user_id) {
                    document.getElementById('unauth-section').style.display = 'none';
                    document.getElementById('auth-section').style.display = 'block';
                    document.getElementById('display-user').innerText = result.username;
                    checkCurrentTab(result.user_id, currentBackend, authToken);
                } else {
                    setUnauthenticatedState();
                }
            });
    });
}

function checkCurrentTab(userId, currentBackend, authToken) {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (!tabs || tabs.length === 0) return;
        const currentUrl = tabs[0].url;

        if (!currentUrl || currentUrl.startsWith('chrome://') || currentUrl.startsWith('chrome-extension://') || currentUrl.startsWith('file://') || currentUrl.startsWith('about:')) {
            updateStatus('N/A', 'unknown');
            return;
        }

        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
        };

        fetch(`${currentBackend}/api/check_url`, {
            method: 'POST',
            headers: headers,
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

// ──────────────────────────────────────────────
// Initialization
// ──────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function () {
    // Check session on load
    updateUI();

    // Auto-detect backend from active tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (tabs && tabs[0] && tabs[0].url) {
            const tabUrl = tabs[0].url;
            if (tabUrl.includes('localhost:5000') || tabUrl.includes('127.0.0.1:5000')) {
                chrome.storage.local.set({ backend_url: 'http://127.0.0.1:5000' }, updateUI);
            } else if (tabUrl.includes('dnsguard.onrender.com')) {
                chrome.storage.local.set({ backend_url: 'https://dnsguard.onrender.com' }, updateUI);
            }
        }
    });

    // Refresh the web app dashboard; the backend will redirect to login when needed.
    document.getElementById('go-to-login-btn').addEventListener('click', function () {
        chrome.storage.local.get(['backend_url'], function (result) {
            const currentBackend = result.backend_url || backendUrl;
            chrome.tabs.create({ url: `${currentBackend}/` });
        });
    });
});

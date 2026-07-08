// The default URL of our Flask backend
let backendUrl = "https://dnsguard-backend.onrender.com";

// ──────────────────────────────────────────────
// Session status check and UI update
// ──────────────────────────────────────────────

function updateUI() {
    chrome.storage.local.get(['backend_url', 'user_id', 'username'], function (result) {
        const currentBackend = result.backend_url || backendUrl;
        
        // Update footer and login redirection links
        document.getElementById('dashboard-link').href = currentBackend;

        // Perform active verification with the backend
        fetch(`${currentBackend}/api/session_status`, { credentials: 'include' })
            .then(res => res.json())
            .then(data => {
                if (data.authenticated) {
                    // Update user storage
                    chrome.storage.local.set({
                        user_id: data.user_id || data.id,
                        username: data.username,
                        role: data.role
                    });
                    
                    // Show Auth Section
                    document.getElementById('unauth-section').style.display = 'none';
                    document.getElementById('auth-section').style.display = 'block';
                    document.getElementById('display-user').innerText = data.username;
                    
                    // Check status of the current tab
                    checkCurrentTab(data.user_id || data.id, currentBackend);
                } else {
                    // Clear user storage
                    chrome.storage.local.remove(['user_id', 'username', 'role']);
                    
                    // Show Unauth Section
                    document.getElementById('auth-section').style.display = 'none';
                    document.getElementById('unauth-section').style.display = 'block';
                }
            })
            .catch(err => {
                console.error("Session verification failed:", err);
                // Offline or server down: fallback to stored credentials if they exist
                if (result.username) {
                    document.getElementById('unauth-section').style.display = 'none';
                    document.getElementById('auth-section').style.display = 'block';
                    document.getElementById('display-user').innerText = result.username;
                    checkCurrentTab(result.user_id, currentBackend);
                } else {
                    document.getElementById('auth-section').style.display = 'none';
                    document.getElementById('unauth-section').style.display = 'block';
                }
            });
    });
}

function checkCurrentTab(userId, currentBackend) {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (!tabs || tabs.length === 0) return;
        const currentUrl = tabs[0].url;

        if (!currentUrl || currentUrl.startsWith('chrome://') || currentUrl.startsWith('chrome-extension://') || currentUrl.startsWith('file://') || currentUrl.startsWith('about:')) {
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
            } else if (tabUrl.includes('dnsguard-backend.onrender.com')) {
                chrome.storage.local.set({ backend_url: 'https://dnsguard-backend.onrender.com' }, updateUI);
            }
        }
    });

    // Sign In click handler
    document.getElementById('go-to-login-btn').addEventListener('click', function () {
        chrome.storage.local.get(['backend_url'], function (result) {
            const currentBackend = result.backend_url || backendUrl;
            window.open(`${currentBackend}/login`, '_blank');
        });
    });
});

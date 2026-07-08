document.addEventListener('DOMContentLoaded', function() {
    // Check and update UI based on current storage state
    updateUIFromStorage();

    // Listen for storage changes to dynamically sync the UI when website state changes
    chrome.storage.onChanged.addListener(function(changes, namespace) {
        if (changes.user_id || changes.username) {
            updateUIFromStorage();
        }
    });

    document.getElementById('login-btn').addEventListener('click', handleLogin);
    document.getElementById('logout-btn').addEventListener('click', handleLogout);
});

function updateUIFromStorage() {
    chrome.storage.local.get(['user_id', 'username', 'backend_url'], function(result) {
        const userId = result.user_id;
        const username = result.username;
        const currentBackend = result.backend_url || "https://dnsguard-backend.onrender.com";

        if (userId) {
            // Verify if the session is still active on the server
            fetch(`${currentBackend}/api/session_status`)
                .then(r => r.json())
                .then(data => {
                    if (data.authenticated) {
                        showStatusSection(username);
                        checkCurrentTab(userId, currentBackend);
                    } else {
                        console.log("[DNSGuard Popup] Session invalid on server. Logging out.");
                        forceLocalLogout();
                    }
                })
                .catch(e => {
                    console.error("[DNSGuard Popup] Error checking session status:", e);
                    // On network error, we still show the cached user status so they aren't forced out offline
                    showStatusSection(username);
                    checkCurrentTab(userId, currentBackend);
                });
        } else {
            showLoginSection();
        }
    });
}

function handleLogin() {
    const user = document.getElementById('username').value.trim();
    const pass = document.getElementById('password').value;
    const errEl = document.getElementById('login-error');
    
    if (!user || !pass) {
        errEl.innerText = "Please fill in all fields.";
        errEl.style.display = 'block';
        return;
    }

    chrome.storage.local.get(['backend_url'], function(result) {
        const currentBackend = result.backend_url || "https://dnsguard-backend.onrender.com";
        
        fetch(`${currentBackend}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: user, password: pass })
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                chrome.storage.local.set({ 
                    user_id: data.user_id, 
                    username: data.username, 
                    role: data.role,
                    backend_url: currentBackend
                }, function() {
                    errEl.style.display = 'none';
                    showStatusSection(data.username);
                    checkCurrentTab(data.user_id, currentBackend);
                });
            } else {
                errEl.innerText = data.error || "Login failed";
                errEl.style.display = 'block';
            }
        }).catch(e => {
            errEl.innerText = "Error connecting to server";
            errEl.style.display = 'block';
        });
    });
}

function handleLogout() {
    chrome.storage.local.get(['backend_url'], function(result) {
        const currentBackend = result.backend_url || "https://dnsguard-backend.onrender.com";
        // Optionally notify the backend of logout, but local logout is key
        chrome.storage.local.remove(['user_id', 'username', 'role'], function() {
            showLoginSection();
        });
    });
}

function forceLocalLogout() {
    chrome.storage.local.remove(['user_id', 'username', 'role'], function() {
        showLoginSection();
    });
}

function showLoginSection() {
    document.getElementById('login-section').style.display = 'block';
    document.getElementById('status-section').style.display = 'none';
    document.getElementById('login-error').style.display = 'none';
}

function showStatusSection(username) {
    document.getElementById('login-section').style.display = 'none';
    document.getElementById('status-section').style.display = 'block';
    document.getElementById('display-user').innerText = username;
    document.getElementById('user-info').style.display = 'block';
}

function checkCurrentTab(userId, currentBackend) {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (!tabs || tabs.length === 0) return;
        let currentUrl = tabs[0].url;
        
        if (!currentUrl || currentUrl.startsWith("chrome://") || currentUrl.startsWith("chrome-extension://")) {
            updateStatus("N/A", "unknown");
            return;
        }

        fetch(`${currentBackend}/api/check_url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: currentUrl, user_id: userId })
        })
        .then(response => response.json())
        .then(data => {
            let colorClass = "unknown";
            if (data.status === "Safe") colorClass = "safe";
            else if (data.status === "Suspicious") colorClass = "suspicious";
            else if (data.status === "Malicious") colorClass = "malicious";
            
            updateStatus(data.status, colorClass);
        })
        .catch(err => {
            console.error("Error connecting to backend", err);
            updateStatus("Offline", "unknown");
        });
    });
}

function updateStatus(text, className) {
    const el = document.getElementById('site-status');
    if (el) {
        el.innerText = text;
        el.className = className;
    }
}

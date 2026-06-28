document.addEventListener('DOMContentLoaded', function() {
    // Check login status first
    chrome.storage.local.get(['user_id', 'username'], function(result) {
        if (result.user_id) {
            showStatusSection(result.username);
            checkCurrentTab(result.user_id);
        } else {
            showLoginSection();
        }
    });

    document.getElementById('login-btn').addEventListener('click', handleLogin);
    document.getElementById('logout-btn').addEventListener('click', handleLogout);
});

function handleLogin() {
    const user = document.getElementById('username').value;
    const pass = document.getElementById('password').value;
    const errEl = document.getElementById('login-error');
    
    fetch("https://dnsguard-backend.onrender.com/api/login", {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            chrome.storage.local.set({ user_id: data.user_id, username: data.username }, function() {
                errEl.style.display = 'none';
                showStatusSection(data.username);
                checkCurrentTab(data.user_id);
            });
        } else {
            errEl.innerText = data.error || "Login failed";
            errEl.style.display = 'block';
        }
    }).catch(e => {
        errEl.innerText = "Error connecting to server";
        errEl.style.display = 'block';
    });
}

function handleLogout() {
    chrome.storage.local.remove(['user_id', 'username'], function() {
        showLoginSection();
    });
}

function showLoginSection() {
    document.getElementById('login-section').style.display = 'block';
    document.getElementById('status-section').style.display = 'none';
}

function showStatusSection(username) {
    document.getElementById('login-section').style.display = 'none';
    document.getElementById('status-section').style.display = 'block';
    document.getElementById('display-user').innerText = username;
    document.getElementById('user-info').style.display = 'block';
}

function checkCurrentTab(userId) {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        let currentUrl = tabs[0].url;
        
        if (currentUrl.startsWith("chrome://") || currentUrl.startsWith("chrome-extension://")) {
            updateStatus("N/A", "unknown");
            return;
        }

        fetch("https://dnsguard-backend.onrender.com/api/check_url", {
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
    el.innerText = text;
    el.className = className;
}

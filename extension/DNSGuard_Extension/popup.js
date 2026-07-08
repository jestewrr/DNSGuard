document.addEventListener('DOMContentLoaded', function() {
    checkCurrentTab();
});

function checkCurrentTab() {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (!tabs || !tabs[0]) return;
        let currentUrl = tabs[0].url;
        
        if (!currentUrl || currentUrl.startsWith("chrome://") || currentUrl.startsWith("chrome-extension://") || currentUrl.startsWith("file://") || currentUrl.startsWith("about:")) {
            updateStatus("N/A", "unknown");
            return;
        }

        fetch("https://dnsguard-backend.onrender.com/api/check_url", {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: currentUrl, user_id: null })
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

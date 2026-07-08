document.addEventListener('DOMContentLoaded', function() {
    checkCurrentTab();
    setupSearch();
});

function checkCurrentTab() {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (!tabs || !tabs[0]) return;
        let currentUrl = tabs[0].url;
        
        // Parse blocked URL from the block page if active
        if (currentUrl) {
            try {
                const parsedUrl = new URL(currentUrl);
                if (parsedUrl.protocol === "chrome-extension:" && parsedUrl.pathname.endsWith("/block.html")) {
                    const blockedUrl = parsedUrl.searchParams.get("url");
                    if (blockedUrl) {
                        currentUrl = blockedUrl;
                    }
                }
            } catch (e) {
                console.error("Error parsing tab URL", e);
            }
        }

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

function setupSearch() {
    const searchInput = document.getElementById('search-input');
    const searchResult = document.getElementById('search-result');
    let debounceTimer;

    if (!searchInput || !searchResult) return;

    searchInput.addEventListener('input', function() {
        clearTimeout(debounceTimer);
        const query = searchInput.value.trim();

        if (!query) {
            searchResult.style.display = 'none';
            return;
        }

        debounceTimer = setTimeout(() => {
            // Sanitize query (handle defanged domains like office365-alert-login[.]com or domain[dot]com)
            let sanitizedUrl = query
                .replace(/\[\.\]/g, '.')
                .replace(/\[dot\]/gi, '.')
                .replace(/\s+/g, '');

            if (!sanitizedUrl.startsWith('http://') && !sanitizedUrl.startsWith('https://')) {
                sanitizedUrl = 'http://' + sanitizedUrl;
            }

            searchResult.innerText = "Scanning...";
            searchResult.style.background = "rgba(255, 255, 255, 0.05)";
            searchResult.style.color = "#94a3b8";
            searchResult.style.display = 'block';

            fetch("https://dnsguard-backend.onrender.com/api/check_url", {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: sanitizedUrl, user_id: null })
            })
            .then(r => r.json())
            .then(data => {
                searchResult.style.display = 'block';
                if (data.status === "Safe") {
                    searchResult.innerText = "Safe Domain";
                    searchResult.style.background = "rgba(34, 197, 94, 0.15)";
                    searchResult.style.color = "#4ade80";
                } else if (data.status === "Suspicious") {
                    searchResult.innerText = "Suspicious Domain";
                    searchResult.style.background = "rgba(234, 179, 8, 0.15)";
                    searchResult.style.color = "#facc15";
                } else if (data.status === "Malicious") {
                    searchResult.innerText = "Malicious Domain";
                    searchResult.style.background = "rgba(239, 68, 68, 0.15)";
                    searchResult.style.color = "#f87171";
                } else {
                    searchResult.innerText = `Status: ${data.status}`;
                    searchResult.style.background = "rgba(255, 255, 255, 0.05)";
                    searchResult.style.color = "#94a3b8";
                }
            })
            .catch(err => {
                console.error("Search API error:", err);
                searchResult.innerText = "Error scanning domain";
                searchResult.style.background = "rgba(239, 68, 68, 0.15)";
                searchResult.style.color = "#f87171";
            });
        }, 300); // 300ms debounce
    });
}

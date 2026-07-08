// The default URL of our Flask backend
let backendUrl = "https://dnsguard-backend.onrender.com";
let lastSessionCheckTime = 0;

// Initialize backendUrl from storage
chrome.storage.local.get(['backend_url'], function(result) {
    if (result.backend_url) {
        backendUrl = result.backend_url;
    }
});

// Update backendUrl dynamically when it changes in storage
chrome.storage.onChanged.addListener(function(changes, namespace) {
    if (changes.backend_url) {
        backendUrl = changes.backend_url.newValue || "https://dnsguard-backend.onrender.com";
        console.log("[DNSGuard Background] Active backend updated to:", backendUrl);
    }
});

// Listen for messages from content script or popup to sync session
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "sync_session") {
        console.log("[DNSGuard Background] Received sync_session:", message);
        if (message.authenticated) {
            chrome.storage.local.set({
                user_id: message.user_id,
                username: message.username,
                role: message.role,
                backend_url: message.backend_url
            }, () => {
                console.log("[DNSGuard Background] Stored authenticated state for user:", message.username);
            });
        } else {
            chrome.storage.local.remove(['user_id', 'username', 'role'], () => {
                console.log("[DNSGuard Background] Cleared authenticated state.");
            });
        }
    }
});

// Debounce cache to prevent duplicate requests
const recentlyChecked = new Set();

chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    // Only intercept main_frame (the main document being loaded)
    if (details.type !== "main_frame") {
      return { cancel: false };
    }

    const url = details.url;
    
    // Ignore chrome internal URLs and the extension's own pages
    if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")) {
      return { cancel: false };
    }

    // Ignore backend endpoints to prevent intercepting API traffic
    try {
        const backendHost = new URL(backendUrl).hostname;
        if (url.includes(backendHost) || url.includes("localhost:5000") || url.includes("127.0.0.1:5000")) {
            return { cancel: false };
        }
    } catch (e) {
        // Fallback checks
        if (url.includes("dnsguard-backend.onrender.com")) {
            return { cancel: false };
        }
    }

    // Debounce duplicate URLs within 5 seconds
    if (recentlyChecked.has(url)) {
      return { cancel: false };
    }
    recentlyChecked.add(url);
    setTimeout(() => recentlyChecked.delete(url), 5000);
    
    checkUrlStatus(url, details.tabId);
    
    return { cancel: false }; // Let it proceed initially while we check
  },
  { urls: ["<all_urls>"] }
);

async function checkUrlStatus(url, tabId) {
    try {
        // Retrieve user_id and backend_url from local storage
        chrome.storage.local.get(['user_id', 'backend_url'], async function(result) {
            const userId = result.user_id || null;
            const currentBackend = result.backend_url || backendUrl;

            // Session Verification Optimization: Poll at most once every 60 seconds
            if (userId && (Date.now() - lastSessionCheckTime > 60000)) {
                try {
                    const sessionRes = await fetch(`${currentBackend}/api/session_status`);
                    const sessionData = await sessionRes.json();
                    lastSessionCheckTime = Date.now();
                    
                    if (!sessionData.authenticated) {
                        console.log("[DNSGuard Background] Session expired on backend. Clearing local auth state.");
                        chrome.storage.local.remove(['user_id', 'username', 'role']);
                        return; // Skip URL check since user is no longer validly authenticated
                    }
                } catch (e) {
                    console.warn("[DNSGuard Background] Error verifying session status:", e);
                }
            }

            const checkApiUrl = `${currentBackend}/api/check_url`;
            const response = await fetch(checkApiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url, user_id: userId })
            });
        
            const data = await response.json();
            
            if (data.status === 'Malicious' || data.status === 'Suspicious') {
                // Trigger browser warning notification
                chrome.notifications.create({
                    type: 'basic',
                    iconUrl: 'imagelogo.png',
                    title: `DNSGuard Alert: ${data.status} Website!`,
                    message: `Access to ${url} was blocked for your safety.`,
                    priority: 2
                }, function(notificationId) {
                    if (chrome.runtime.lastError) {
                        console.log("Notification error (e.g. missing icon):", chrome.runtime.lastError);
                    }
                });

                // Determine reason from breakdown
                let reason = "Classified as unsafe by threat engine.";
                if (data.breakdown) {
                    for (const check of Object.values(data.breakdown)) {
                        if (check.status === 'Failed' && check.message) {
                            reason = check.message;
                            break;
                        }
                    }
                }

                // Redirect the tab to our block page
                const blockUrl = chrome.runtime.getURL(`block.html?url=${encodeURIComponent(url)}&status=${data.status}&reason=${encodeURIComponent(reason)}`);
                chrome.tabs.update(tabId, { url: blockUrl });
            }
        }); // end storage get
    } catch (error) {
        console.error("DNSGuard API Error:", error);
    }
}

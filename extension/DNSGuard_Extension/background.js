// The URL of our local Flask backend
const BACKEND_URL = "https://dnsguard-backend.onrender.com/api/check_url";

// Debounce cache to prevent duplicate requests
const recentlyChecked = new Set();

// Local cache for URL check results (domain -> { status, reason, expireTime })
const domainCache = new Map();

function extractDomain(url) {
    try {
        const parsed = new URL(url);
        let domain = parsed.hostname;
        if (domain.startsWith("www.")) {
            domain = domain.substring(4);
        }
        return domain;
    } catch (e) {
        return "";
    }
}

chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    // Only intercept main_frame (the main document being loaded)
    if (details.type !== "main_frame") {
      return { cancel: false };
    }

    const url = details.url;
    
    // Ignore chrome internal URLs, about:blank, local files, and the dashboard itself
    if (url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("file://") || url.startsWith("about:") || url.includes("dnsguard-backend.onrender.com")) {
      return { cancel: false };
    }

    const domain = extractDomain(url);
    if (!domain) {
      return { cancel: false };
    }

    // Check local domain cache for instant responses
    if (domainCache.has(domain)) {
        const cached = domainCache.get(domain);
        if (Date.now() < cached.expireTime) {
            if (cached.status === 'Malicious' || cached.status === 'Suspicious') {
                const blockUrl = chrome.runtime.getURL(`block.html?url=${encodeURIComponent(url)}&status=${cached.status}&reason=${encodeURIComponent(cached.reason)}`);
                chrome.tabs.update(details.tabId, { url: blockUrl });
                return { cancel: true };
            }
            return { cancel: false }; // Cached as Safe, let it proceed immediately
        } else {
            domainCache.delete(domain);
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
        const domain = extractDomain(url);

        const response = await fetch(BACKEND_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url, user_id: null })
        });
    
        const data = await response.json();
        
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

        // Cache the result for 5 minutes (300,000 ms)
        if (domain) {
            domainCache.set(domain, {
                status: data.status,
                reason: reason,
                expireTime: Date.now() + 5 * 60 * 1000
            });
        }

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

            // Redirect the tab to our block page
            const blockUrl = chrome.runtime.getURL(`block.html?url=${encodeURIComponent(url)}&status=${data.status}&reason=${encodeURIComponent(reason)}`);
            chrome.tabs.update(tabId, { url: blockUrl });
        }
    } catch (error) {
        console.error("DNSGuard API Error:", error);
    }
}

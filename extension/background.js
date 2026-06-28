// The URL of our local Flask backend
const BACKEND_URL = "http://localhost:5000/api/check_url";

chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    // Only intercept main_frame (the main document being loaded)
    if (details.type !== "main_frame") {
      return { cancel: false };
    }

    const url = details.url;
    
    // Ignore chrome internal URLs
    if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")) {
      return { cancel: false };
    }

    // Since onBeforeRequest in MV3 cannot be asynchronous when blocking (using async/await or promises to block),
    // we use a synchronous XMLHttpRequest workaround or use declarativeNetRequest in a real prod environment.
    // However, MV3 dropped support for blocking webRequest.
    // Wait, MV3 requires declarativeNetRequest for blocking, OR we can let it load, check async, and redirect if bad.
    // Let's implement the async check and redirect pattern for simplicity.
    
    checkUrlStatus(url, details.tabId);
    
    return { cancel: false }; // Let it proceed initially while we check
  },
  { urls: ["<all_urls>"] }
);

async function checkUrlStatus(url, tabId) {
    try {
        // Retrieve user_id from local storage if they are logged in
        chrome.storage.local.get(['user_id'], async function(result) {
            const userId = result.user_id || null;

            const response = await fetch(BACKEND_URL, {
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
                iconUrl: 'icon.png', // Requires an icon file in the extension directory
                title: `DNSGuard Alert: ${data.status} Website!`,
                message: `Access to ${url} was blocked for your safety.`,
                priority: 2
            }, function(notificationId) {
                if (chrome.runtime.lastError) {
                    console.log("Notification error (e.g. missing icon):", chrome.runtime.lastError);
                }
            });

            // Redirect the tab to our block page
            const blockUrl = chrome.runtime.getURL(`block.html?url=${encodeURIComponent(url)}&status=${data.status}`);
            chrome.tabs.update(tabId, { url: blockUrl });
        }
        }); // end storage get
    } catch (error) {
        console.error("DNSGuard API Error:", error);
    }
}

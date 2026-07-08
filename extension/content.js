(async function() {
    const origin = window.location.origin;
    
    async function checkAndSync() {
        try {
            const response = await fetch('/api/session_status');
            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }
            const data = await response.json();
            
            chrome.runtime.sendMessage({
                action: "sync_session",
                authenticated: !!data.authenticated,
                user_id: data.user_id || data.id || null,
                username: data.username || null,
                role: data.role || null,
                backend_url: origin
            });
            console.log("[DNSGuard Content Script] Session status synced:", data.authenticated ? `user=${data.username}` : 'unauthenticated');
        } catch (e) {
            console.error("[DNSGuard Content Script] Error checking session status:", e);
        }
    }

    // Run immediately on page load
    checkAndSync();
    
    // Periodically sync every 15 seconds to catch session expiration/changes
    setInterval(checkAndSync, 15000);
})();

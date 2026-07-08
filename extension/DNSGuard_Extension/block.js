const urlParams = new URLSearchParams(window.location.search);
const url = urlParams.get('url');
const status = urlParams.get('status');
const reason = urlParams.get('reason');

if (url) document.getElementById('blocked-url').innerText = url;
if (status) document.getElementById('status-text').innerText = status;
if (reason) document.getElementById('reason-text').innerText = "Reason: " + reason;

const container = document.getElementById('main-container');
const titleText = document.getElementById('title-text');

if (status === 'Suspicious') {
    if (container) container.classList.add('suspicious');
    if (titleText) titleText.textContent = 'Suspicious Site Detected';
} else {
    if (container) container.classList.add('malicious');
}

document.getElementById('go-back-btn').addEventListener('click', function() {
    if (window.history.length > 1) {
        window.history.back();
    } else {
        window.close(); // Try to close the tab if opened in a new tab
        setTimeout(() => {
            window.location.href = "https://google.com";
        }, 100);
    }
});

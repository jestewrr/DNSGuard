const urlParams = new URLSearchParams(window.location.search);
const url = urlParams.get('url');
const status = urlParams.get('status');
const reason = urlParams.get('reason');

if (url) document.getElementById('blocked-url').innerText = url;
if (status) document.getElementById('status-text').innerText = status;
if (reason) document.getElementById('reason-text').innerText = "Reason: " + reason;

const container = document.getElementById('main-container');
if (status === 'Suspicious') {
    container.classList.add('suspicious');
    document.querySelector('h1').textContent = 'Suspicious Site Detected';
} else {
    container.classList.add('malicious');
}

document.getElementById('go-back-btn').addEventListener('click', function() {
    window.history.back();
});

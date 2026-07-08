function togglePw(id) {
    const el = document.getElementById(id);
    el.type = el.type === 'password' ? 'text' : 'password';
}

async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-toggle-password]').forEach((button) => {
        button.addEventListener('click', function () {
            togglePw(this.getAttribute('data-toggle-password'));
        });
    });

    const registerForm = document.getElementById('registerForm');
    if (!registerForm) {
        return;
    }

    registerForm.addEventListener('submit', async function (e) {
        e.preventDefault();
        const pwInput = document.getElementById('passwordInput');
        const cpwInput = document.getElementById('confirmInput');

        if (pwInput.value !== cpwInput.value) {
            document.getElementById('matchError').classList.remove('hidden');
            return;
        }

        document.getElementById('btnText').textContent = 'Creating account...';
        document.getElementById('btnSpinner').classList.remove('hidden');
        document.getElementById('submitBtn').disabled = true;

        const hashedPw = await sha256(pwInput.value);
        pwInput.value = hashedPw;
        cpwInput.value = hashedPw;

        this.submit();
    });
});

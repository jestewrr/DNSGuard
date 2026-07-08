function togglePassword() {
    const input = document.getElementById('passwordInput');
    const icon = document.getElementById('eyeIcon');
    if (input.type === 'password') {
        input.type = 'text';
        icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L3 3m6.878 6.878L21 21"></path>';
    } else {
        input.type = 'password';
        icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>';
    }
}

async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

document.addEventListener('DOMContentLoaded', function () {
    const toggleButton = document.getElementById('togglePasswordBtn');
    if (toggleButton) {
        toggleButton.addEventListener('click', togglePassword);
    }

    const loginForm = document.getElementById('loginForm');
    if (!loginForm) {
        return;
    }

    loginForm.addEventListener('submit', async function (e) {
        e.preventDefault();
        document.getElementById('btnText').textContent = 'Signing in...';
        document.getElementById('btnSpinner').classList.remove('hidden');
        document.getElementById('submitBtn').disabled = true;

        const pwInput = document.getElementById('passwordInput');
        pwInput.value = await sha256(pwInput.value);

        this.submit();
    });
});

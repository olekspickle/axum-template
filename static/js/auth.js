// Login form handler
document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('error-message');

            try {
                const formData = new URLSearchParams();
                formData.append('username', username);
                formData.append('password', password);
                const remember = document.getElementById('remember');
                if (remember && remember.checked) {
                    formData.append('remember', 'on');
                }

                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: formData,
                    credentials: 'same-origin'
                });

                if (response.ok) {
                    window.location.href = '/admin';
                } else {
                    const data = await response.json();
                    errorDiv.textContent = data.error || 'Login failed';
                    errorDiv.classList.remove('hidden');
                }
            } catch (err) {
                errorDiv.textContent = 'Network error. Please try again.';
                errorDiv.classList.remove('hidden');
            }
        });
    }

    // Forgot password form handler
    const forgotForm = document.getElementById('forgot-form');
    if (forgotForm) {
        forgotForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const errorDiv = document.getElementById('error-message');
            const successDiv = document.getElementById('success-message');

            try {
                const formData = new URLSearchParams();
                formData.append('username', username);

                const response = await fetch('/admin/forgot-password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: formData,
                });

                const data = await response.json();
                if (response.ok) {
                    successDiv.textContent = data.message || 'Reset instructions sent';
                    successDiv.classList.remove('hidden');
                    errorDiv.classList.add('hidden');
                    if (data.reset_token) {
                        successDiv.textContent += ' (Dev: ' + data.reset_token + ')';
                    }
                } else {
                    errorDiv.textContent = data.error || 'Request failed';
                    errorDiv.classList.remove('hidden');
                    successDiv.classList.add('hidden');
                }
            } catch (err) {
                errorDiv.textContent = 'Network error. Please try again.';
                errorDiv.classList.remove('hidden');
            }
        });
    }

    // Reset password form handler
    const resetForm = document.getElementById('reset-form');
    if (resetForm) {
        resetForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const token = document.getElementById('token').value;
            const newPassword = document.getElementById('new_password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            const errorDiv = document.getElementById('error-message');
            const successDiv = document.getElementById('success-message');

            if (newPassword !== confirmPassword) {
                errorDiv.textContent = 'Passwords do not match';
                errorDiv.classList.remove('hidden');
                return;
            }

            try {
                const formData = new URLSearchParams();
                formData.append('token', token);
                formData.append('new_password', newPassword);

                const response = await fetch('/admin/reset-password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: formData,
                });

                const data = await response.json();
                if (response.ok) {
                    successDiv.textContent = data.message || 'Password reset successful';
                    successDiv.classList.remove('hidden');
                    errorDiv.classList.add('hidden');
                    setTimeout(() => {
                        window.location.href = '/login';
                    }, 2000);
                } else {
                    errorDiv.textContent = data.error || 'Reset failed';
                    errorDiv.classList.remove('hidden');
                    successDiv.classList.add('hidden');
                }
            } catch (err) {
                errorDiv.textContent = 'Network error. Please try again.';
                errorDiv.classList.remove('hidden');
            }
        });
    }
});

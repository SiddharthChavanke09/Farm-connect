async function loginUser() {
    // Get form data
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value.trim();

    // Clear previous errors
    clearErrors();

    // Basic validation
    if (!email || !password) {
        if (!email) showError('email', 'Email is required');
        if (!password) showError('password', 'Password is required');
        return;
    }

    // Admin login handling
    if (email === 'admin@farmconnect.com' && password === 'admin123') {
        const adminData = {
            email: 'admin@farmconnect.com',
            role: 'admin',
            name: 'Admin User'
        };

        // Set token expiry to 24 hours from now
        const tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
        
        // Store admin data with expiry
        localStorage.setItem('userData', JSON.stringify(adminData));
        localStorage.setItem('userRole', 'admin');
        localStorage.setItem('token', 'admin-token'); // You might want to generate a real token
        localStorage.setItem('tokenExpiry', tokenExpiry);

        // Show success message
        const successDiv = document.createElement('div');
        successDiv.style.backgroundColor = '#4caf50';
        successDiv.style.color = 'white';
        successDiv.style.padding = '10px';
        successDiv.style.borderRadius = '4px';
        successDiv.style.marginBottom = '10px';
        successDiv.style.textAlign = 'center';
        successDiv.textContent = 'Admin login successful! Redirecting...';

        const form = document.getElementById('loginForm');
        form.insertAdjacentElement('beforebegin', successDiv);

        // Use replace instead of href to prevent back button
        setTimeout(() => {
            window.location.replace('dashboard.html');
        }, 1500);

        return;
    }

    try {
        const response = await fetch('http://localhost:3000/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (response.ok) {
            // Store token, expiry and user data
            localStorage.setItem('token', data.token);
            localStorage.setItem('tokenExpiry', data.tokenExpiry);
            localStorage.setItem('userRole', data.user.role);
            localStorage.setItem('userData', JSON.stringify(data.user));

            // Show success message
            showSuccessMessage('Login successful! Redirecting...');

            // Redirect based on user role after a short delay
            setTimeout(() => {
                switch (data.user.role) {
                    case 'farmer':
                        window.location.replace('farmer_dashboard.html');
                        break;
                    case 'admin':
                        window.location.replace('dashboard.html');
                        break;
                    case 'customer':
                        window.location.replace('customer_dashboard.html');
                        break;
                    default:
                        window.location.replace('customer_dashboard.html');
                }
            }, 1500);
        } else {
            showErrorMessage(data.error || 'Login failed. Please try again.');
        }
    } catch (error) {
        console.error('Error:', error);
        showErrorMessage('Failed to connect to server. Please try again.');
    }
}

function showSuccessMessage(message) {
    const successDiv = document.createElement('div');
    successDiv.style.backgroundColor = '#4caf50';
    successDiv.style.color = 'white';
    successDiv.style.padding = '10px';
    successDiv.style.borderRadius = '4px';
    successDiv.style.marginBottom = '10px';
    successDiv.textContent = message;
    document.querySelector('.login-body').insertBefore(successDiv, document.querySelector('form'));
}

function showErrorMessage(message) {
    const errorDiv = document.createElement('div');
    errorDiv.style.backgroundColor = '#f44336';
    errorDiv.style.color = 'white';
    errorDiv.style.padding = '10px';
    errorDiv.style.borderRadius = '4px';
    errorDiv.style.marginBottom = '10px';
    errorDiv.textContent = message;
    document.querySelector('.login-body').insertBefore(errorDiv, document.querySelector('form'));
}

function showError(inputId, message) {
    const input = document.getElementById(inputId);
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.style.color = '#f44336';
    errorDiv.style.fontSize = '12px';
    errorDiv.style.marginTop = '5px';
    errorDiv.textContent = message;
    input.parentNode.appendChild(errorDiv);
    input.style.borderColor = '#f44336';
}

function clearErrors() {
    const errors = document.querySelectorAll('.error-message');
    errors.forEach(error => error.remove());
    const inputs = document.querySelectorAll('input');
    inputs.forEach(input => input.style.borderColor = '');
    const messages = document.querySelectorAll('.login-body > div');
    messages.forEach(msg => {
        if (msg.tagName !== 'FORM') msg.remove();
    });
}

function checkAuthStatus() {
    const token = localStorage.getItem('token');
    const tokenExpiry = localStorage.getItem('tokenExpiry');
    const userRole = localStorage.getItem('userRole');

    if (token && tokenExpiry && new Date(tokenExpiry) > new Date()) {
        // Token exists and is not expired
        switch (userRole) {
            case 'farmer':
                window.location.replace('farmer_dashboard.html');
                break;
            case 'admin':
                window.location.replace('dashboard.html');
                break;
            case 'customer':
                window.location.replace('customer_dashboard.html');
                break;
        }
    } else {
        // Clear any expired tokens
        localStorage.removeItem('token');
        localStorage.removeItem('tokenExpiry');
        localStorage.removeItem('userRole');
        localStorage.removeItem('userData');
    }
}

// Check auth status when page loads
document.addEventListener('DOMContentLoaded', checkAuthStatus);

// Check for stored login credentials on page load
document.addEventListener('DOMContentLoaded', function() {
    const tempEmail = sessionStorage.getItem('tempLoginEmail');
    const tempPassword = sessionStorage.getItem('tempLoginPassword');
    
    if (tempEmail && tempPassword) {
        document.getElementById('email').value = tempEmail;
        document.getElementById('password').value = tempPassword;
        
        // Clear the stored credentials
        sessionStorage.removeItem('tempLoginEmail');
        sessionStorage.removeItem('tempLoginPassword');
        
        // Auto submit the form
        loginUser();
    }
});
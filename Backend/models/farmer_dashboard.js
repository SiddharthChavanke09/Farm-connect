// Check authentication and user role
document.addEventListener('DOMContentLoaded', () => {
  // Check if user is logged in and is a farmer
  const token = localStorage.getItem('token');
  const userRole = localStorage.getItem('userRole');
  const userData = JSON.parse(localStorage.getItem('userData') || '{}');

  if (!token || userRole !== 'farmer') {
    // If not logged in or not a farmer, redirect to login
    window.location.href = 'login.html';
    return;
  }

  // Update user information in the header
  if (userData) {
    document.getElementById('userName').textContent = userData.firstName + ' ' + userData.lastName;
    document.getElementById('userAvatar').textContent = 
      userData.firstName.charAt(0) + userData.lastName.charAt(0);
  }

  // Add logout functionality
  document.querySelector('a[href="login.html"]').addEventListener('click', (e) => {
    e.preventDefault();
    // Clear all authentication data
    localStorage.removeItem('token');
    localStorage.removeItem('userRole');
    localStorage.removeItem('userData');
    // Redirect to login
    window.location.href = 'login.html';
  });
});
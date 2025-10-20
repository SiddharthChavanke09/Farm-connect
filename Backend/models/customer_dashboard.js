// customer_dashboard.js - Fixed version
// Check authentication and user role
function checkAuth() {
  const token = localStorage.getItem('token');
  const userRole = localStorage.getItem('userRole');
  const userData = JSON.parse(localStorage.getItem('userData') || '{}');
  
  if (!token || userRole !== 'customer') {
    window.location.href = 'login.html';
    return;
  }
  
  // Update UI with user data
  document.getElementById('userName').textContent = `${userData.firstName} ${userData.lastName}`;
  document.getElementById('userAvatar').src = userData.avatar || 'https://randomuser.me/api/portraits/women/44.jpg';
  document.getElementById('headerAvatar').src = userData.avatar || 'https://randomuser.me/api/portraits/women/44.jpg';
  
  // Load customer orders
  if (userData.id) {
    fetchCustomerOrders(userData.id);
  }
}

// Fetch customer orders
async function fetchCustomerOrders(customerId) {
  try {
    const token = localStorage.getItem('token');
    const response = await fetch(`http://localhost:3000/api/customer/orders/${customerId}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!response.ok) throw new Error('Failed to fetch orders');
    const orders = await response.json();
    updateOrdersTable(orders);
  } catch (error) {
    console.error('Error fetching orders:', error);
  }
}

function updateOrdersTable(orders) {
  const tableBody = document.querySelector('.orders-table tbody');
  if (!tableBody) return;
  
  if (orders.length === 0) {
    tableBody.innerHTML = `<tr><td colspan="5" style="text-align: center;">No orders found</td></tr>`;
    return;
  }
  
  tableBody.innerHTML = orders.map(order => `
      <tr>
          <td>${order.orderId || 'N/A'}</td>
          <td>${new Date(order.createdAt).toLocaleDateString()}</td>
          <td>₹${order.totalAmount ? order.totalAmount.toFixed(2) : '0.00'}</td>
          <td><span class="order-status status-${order.status ? order.status.toLowerCase() : 'pending'}">${order.status || 'Pending'}</span></td>
          <td>
              <button class="action-btn view">View</button>
              <button class="action-btn track">Track</button>
          </td>
      </tr>
  `).join('');
}

function logout() {
  localStorage.clear();
  window.location.href = 'login.html';
}

// Call checkAuth when page loads
document.addEventListener('DOMContentLoaded', checkAuth);
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:5500', 'http://localhost:5500', 'http://localhost:8000'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/farmconnect';

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB successfully'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// --- FarmVisit Schema & Model ---
const farmVisitSchema = new mongoose.Schema({
    customerName: { type: String, required: true },
    customerEmail: { type: String, required: true },
    customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    farmerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    farmerName: { type: String, required: true },
    visitDate: { type: Date, required: true },
    purpose: { type: String, required: true },
    status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' },
}, {
    timestamps: true
});

const FarmVisit = mongoose.model('FarmVisit', farmVisitSchema);

// --- Product Schema & Model ---
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  category: { type: String, required: true },
  price: { type: Number, required: true },
  quantity: { type: Number, required: true },
  description: { type: String },
  farmer: {
    id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true }
  },
  image: { type: String },
}, {
  timestamps: true
});

const Product = mongoose.model('Product', productSchema);

// User Schema (for all users - farmers, customers, admins)
const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
    trim: true
  },
  lastName: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  phone: {
    type: String,
    required: true,
    trim: true
  },
  role: {
    type: String,
    enum: ['farmer', 'customer', 'admin'],
    required: true,
    default: 'customer'
  },
  // Farmer specific fields
  farmName: {
    type: String,
    trim: true
  },
  farmLocation: {
    type: String,
    trim: true
  },
  about: {
    type: String,
    trim: true
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  // Customer specific fields
  address: {
    street: String,
    city: String,
    state: String,
    zipCode: String
  },
  products: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Product'
  }],
}, {
  timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Order Schema
const orderSchema = new mongoose.Schema({
  orderId: {
    type: String,
    required: true,
    unique: true
  },
  customerEmail: {
    type: String,
    required: true
  },
  customerName: {
    type: String,
    required: true
  },
  vegetable: {
    type: String,
    required: true
  },
  quantity: {
    type: Number,
    required: true,
    min: 1
  },
  deliveryAddress: {
    type: String,
    required: true
  },
  totalAmount: {
    type: Number,
    required: true
  },
  status: {
    type: String,
    enum: ['placed', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'],
    default: 'placed'
  }
}, {
  timestamps: true
});

const Order = mongoose.model('Order', orderSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Auth middleware
const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).json({ error: 'Invalid token.' });
  }
};

// Admin auth middleware
const adminAuth = (req, res, next) => {
    try {
        const authHeader = req.header('Authorization');
        console.log('Auth header received:', authHeader); // Debug log

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'No token provided or invalid format' });
        }

        const token = authHeader.replace('Bearer ', '');
        console.log('Token extracted:', token); // Debug log

        // Special case for hardcoded admin token
        if (token === 'admin-token') {
            req.user = {
                id: 'admin',
                email: 'admin@farmconnect.com',
                role: 'admin',
                name: 'Admin User'
            };
            return next();
        }

        // For regular JWT tokens
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log('Decoded token:', decoded); // Debug log

        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Not authorized as admin' });
        }

        req.user = decoded;
        next();
    } catch (error) {
        console.error('Admin auth error:', error);
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'Invalid token' });
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired' });
        }
        res.status(500).json({ error: 'Authentication error' });
    }
};

// Routes

// Test route
app.get('/api/test', (req, res) => {
  res.json({ message: 'FarmConnect Backend is running!' });
});

// Check email availability
app.get('/api/check-email', async (req, res) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    const user = await User.findOne({ email: email.toLowerCase() });
    
    res.json({ exists: !!user });
  } catch (error) {
    console.error('Check email error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Create admin user (run once to create admin)
app.post('/api/create-admin', async (req, res) => {
  try {
    const { firstName, lastName, email, password, phone } = req.body;

    if (!firstName || !lastName || !email || !password || !phone) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if admin already exists
    const existingAdmin = await User.findOne({ email: email.toLowerCase(), role: 'admin' });
    if (existingAdmin) {
      return res.status(400).json({ error: 'Admin already exists' });
    }

    // Create admin user
    const admin = new User({
      firstName,
      lastName,
      email: email.toLowerCase(),
      password,
      phone,
      role: 'admin'
    });

    await admin.save();

    res.status(201).json({ message: 'Admin user created successfully' });
  } catch (error) {
    console.error('Create admin error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Check for admin in the database
    const admin = await User.findOne({ email: email.toLowerCase(), role: 'admin' });
    
    if (!admin) {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }

    // Verify password
    const isPasswordValid = await admin.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }

    // Generate token
    const token = jwt.sign(
      { 
        id: admin._id, 
        email: admin.email, 
        role: 'admin',
        name: `${admin.firstName} ${admin.lastName}`
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Admin login successful',
      token,
      user: {
        id: admin._id,
        firstName: admin.firstName,
        lastName: admin.lastName,
        email: admin.email,
        role: 'admin'
      }
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get all users and stats for Admin Dashboard (Admin only)
app.get('/api/admin/dashboard-data', adminAuth, async (req, res) => {
    try {
        console.log('Admin token:', req.header('Authorization')); // Debug log

        // Fetch all users with role-based filtering
        const [farmers, customers, products, orders] = await Promise.all([
            User.find({ role: 'farmer' })
                .select('-password')
                .sort({ createdAt: -1 })
                .lean(),
            
            User.find({ role: 'customer' })
                .select('-password')
                .sort({ createdAt: -1 })
                .lean(),
            
            Product.find().lean(),
            Order.find().lean()
        ]);

        console.log('Data counts:', { 
            farmers: farmers.length, 
            customers: customers.length,
            products: products.length,
            orders: orders.length
        }); // Debug log

        // Send response
        res.json({
            farmers,
            customers,
            productsCount: products.length,
            ordersCount: orders.length,
            orderStats: [], // Add order stats if needed
            recentOrders: orders.slice(0, 5)
        });

    } catch (error) {
        console.error('Admin dashboard data error:', error);
        res.status(500).json({ 
            error: 'Failed to fetch dashboard data',
            details: error.message
        });
    }
});

// Get all users for admin (Admin only)
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const farmers = await User.find({ role: 'farmer' }).select('-password');
    const customers = await User.find({ role: 'customer' }).select('-password');
    
    res.json({
      farmers,
      customers
    });
  } catch (error) {
    console.error('Get admin users error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Customer Registration - Specific endpoint
app.post('/api/register/customer', async (req, res) => {
  try {
    const { firstName, lastName, email, password, phone, address } = req.body;

    // Validation
    if (!firstName || !lastName || !email || !password || !phone) {
      return res.status(400).json({ error: 'All required fields must be filled' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Create new customer user
    const user = new User({
      firstName,
      lastName,
      email: email.toLowerCase(),
      password,
      phone,
      role: 'customer',
      address: address
    });

    const savedUser = await user.save();

    // Generate token
    const token = jwt.sign(
      { 
        id: savedUser._id, 
        email: savedUser.email, 
        role: savedUser.role,
        name: `${savedUser.firstName} ${savedUser.lastName}`
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'Customer registered successfully',
      token,
      user: {
        id: savedUser._id,
        firstName: savedUser.firstName,
        lastName: savedUser.lastName,
        email: savedUser.email,
        role: savedUser.role,
        address: savedUser.address
      }
    });
  } catch (error) {
    console.error('Customer registration error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Farmer Registration Endpoint
app.post('/api/farmers/register', async (req, res) => {
  try {
    const { firstName, lastName, email, password, phone, farmName, farmLocation, about } = req.body;

    // Validation
    if (!firstName || !lastName || !email || !password || !phone || !farmName || !farmLocation) {
      return res.status(400).json({ error: 'All required fields must be filled' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Create new farmer user
    const user = new User({
      firstName,
      lastName,
      email: email.toLowerCase(),
      password,
      phone,
      role: 'farmer',
      farmName,
      farmLocation,
      about
    });

    const savedUser = await user.save();

    // Generate token
    const token = jwt.sign(
      { 
        id: savedUser._id, 
        email: savedUser.email, 
        role: savedUser.role,
        name: `${savedUser.firstName} ${savedUser.lastName}`
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'Farmer registered successfully',
      token,
      user: {
        id: savedUser._id,
        firstName: savedUser.firstName,
        lastName: savedUser.lastName,
        email: savedUser.email,
        role: savedUser.role,
        farmName: savedUser.farmName,
        farmLocation: savedUser.farmLocation
      }
    });
  } catch (error) {
    console.error('Farmer registration error:', error);
    res.status(500).json({ error: error.message });
  }
});

// General User Registration
app.post('/api/register', async (req, res) => {
  try {
    const { firstName, lastName, email, password, phone, role, farmName, farmLocation, about, address } = req.body;

    // Validation
    if (!firstName || !lastName || !email || !password || !phone || !role) {
      return res.status(400).json({ error: 'All required fields must be filled' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Create new user
    const user = new User({
      firstName,
      lastName,
      email: email.toLowerCase(),
      password,
      phone,
      role,
      ...(role === 'farmer' && { farmName, farmLocation, about }),
      ...(role === 'customer' && { address })
    });

    const savedUser = await user.save();

    // Generate token
    const token = jwt.sign(
      { 
        id: savedUser._id, 
        email: savedUser.email, 
        role: savedUser.role,
        name: `${savedUser.firstName} ${savedUser.lastName}`
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: savedUser._id,
        firstName: savedUser.firstName,
        lastName: savedUser.lastName,
        email: savedUser.email,
        role: savedUser.role,
        ...(savedUser.role === 'farmer' && { farmName: savedUser.farmName }),
        ...(savedUser.role === 'customer' && { address: savedUser.address })
      }
    });
  } catch (error) {
    console.error('User registration error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Login for all users
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ email: email.toLowerCase() });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate token with longer expiration
    const token = jwt.sign(
      { 
        id: user._id, 
        email: user.email, 
        role: user.role,
        name: `${user.firstName} ${user.lastName}`
      },
      JWT_SECRET,
      { expiresIn: '30d' } // Extended to 30 days
    );

    // Set token expiry in response
    res.json({
      message: 'Login successful',
      token,
      tokenExpiry: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        ...(user.role === 'farmer' && { 
          farmName: user.farmName,
          farmLocation: user.farmLocation
        }),
        ...(user.role === 'customer' && { address: user.address })
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get User Profile (Protected)
app.get('/api/profile', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    console.error('Get user profile error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get customer orders
app.get('/api/customer/orders', auth, async (req, res) => {
  try {
    if (req.user.role !== 'customer') {
      return res.status(403).json({ error: 'Access denied. Customers only.' });
    }

    const orders = await Order.find({ customerEmail: req.user.email }).sort({ createdAt: -1 });
    
    res.json(orders);
  } catch (error) {
    console.error('Get customer orders error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ORDER MANAGEMENT ROUTES

// Create a new order
app.post('/api/orders', async (req, res) => {
  try {
    const { customerEmail, customerName, vegetable, quantity, deliveryAddress, totalAmount } = req.body;

    // Validation
    if (!customerEmail || !customerName || !vegetable || !quantity || !deliveryAddress || !totalAmount) {
      return res.status(400).json({ error: 'All required fields must be filled' });
    }

    // Generate order ID
    const orderId = 'ORD' + Date.now() + Math.floor(Math.random() * 1000);

    // Create new order
    const order = new Order({
      orderId,
      customerEmail,
      customerName,
      vegetable,
      quantity,
      deliveryAddress,
      totalAmount,
      status: 'placed'
    });

    const savedOrder = await order.save();

    res.status(201).json({
      message: 'Order placed successfully',
      order: savedOrder
    });
  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get order by ID
app.get('/api/orders/:orderId', async (req, res) => {
  try {
    const order = await Order.findOne({ orderId: req.params.orderId });
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    res.json(order);
  } catch (error) {
    console.error('Get order error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get orders by customer email
app.get('/api/orders/customer/:email', async (req, res) => {
  try {
    const orders = await Order.find({ customerEmail: req.params.email }).sort({ createdAt: -1 });
    
    res.json({
      orders,
      totalOrders: orders.length
    });
  } catch (error) {
    console.error('Get customer orders error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Update order status
app.patch('/api/orders/:orderId/status', async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!status) {
      return res.status(400).json({ error: 'Status is required' });
    }

    const validStatuses = ['placed', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const order = await Order.findOneAndUpdate(
      { orderId: req.params.orderId },
      { status },
      { new: true }
    );

    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    res.json({
      message: 'Order status updated successfully',
      order
  });
  } catch (error) {
    console.error('Update order status error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get all orders (Admin only)
app.get('/api/admin/orders', adminAuth, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 });
    
    res.json({
      orders,
      totalOrders: orders.length
    });
  } catch (error) {
    console.error('Get all orders error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get orders for farmer
app.get('/api/farmer/orders', auth, async (req, res) => {
  try {
    if (req.user.role !== 'farmer') {
      return res.status(403).json({ error: 'Access denied. Farmers only.' });
    }

    // Get orders (in a real app, you would filter by farmer's products)
    const orders = await Order.find().sort({ createdAt: -1 });
    
    res.json({
      orders,
      totalOrders: orders.length
    });
  } catch (error) {
    console.error('Get farmer orders error:', error);
    res.status(500).json({ error: error.message });
  }
});

// --- Farmer Product Routes ---
// Add a new product (Farmer only)
app.post('/api/farmer/products', auth, async (req, res) => {
  try {
    // Check if user is a farmer
    if (req.user.role !== 'farmer') {
      return res.status(403).json({ error: 'Access denied. Farmers only.' });
    }

    const { name, category, price, quantity, description, image } = req.body;

    if (!name || !category || !price || !quantity) {
      return res.status(400).json({ error: 'Missing required product fields' });
    }

    const newProduct = new Product({
      name,
      category,
      price,
      quantity,
      description,
      image,
      farmer: {
        id: req.user.id,
        name: req.user.name
      }
    });

    await newProduct.save();

    res.status(201).json({ message: 'Product added successfully', product: newProduct });
  } catch (error) {
    console.error('Add product error:', error);
    res.status(500).json({ error: 'Failed to add product' });
  }
});

// Get all products (Public route)
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.json(products);
  } catch (error) {
    console.error('Get products error:', error);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// --- Farm Visit Routes ---

// Get Active Farmers for visit requests
app.get('/api/farmers', auth, async (req, res) => {
    try {
        const farmers = await User.find({ role: 'farmer', isVerified: true }).select('firstName lastName farmName');
        res.json(farmers);
    } catch (error) {
        console.error('Error fetching farmers:', error);
        res.status(500).json({ error: 'Failed to fetch farmers.' });
    }
});

// Request a farm visit (Customer only)
app.post('/api/visits/request', auth, async (req, res) => {
    if (req.user.role !== 'customer') {
        return res.status(403).json({ error: 'Only customers can request visits.' });
    }
    try {
        const { farmerId, visitDate, purpose } = req.body;
        
        const farmer = await User.findById(farmerId);
        if (!farmer || farmer.role !== 'farmer') {
            return res.status(404).json({ error: 'Farmer not found.' });
        }
        
        const newVisit = new FarmVisit({
            customerName: req.user.name,
            customerEmail: req.user.email,
            customerId: req.user.id,
            farmerId: farmer._id,
            farmerName: `${farmer.firstName} ${farmer.lastName}`,
            visitDate,
            purpose
        });

        await newVisit.save();
        res.status(201).json({ message: 'Visit request submitted successfully.', visit: newVisit });

    } catch (error) {
        console.error('Error creating visit request:', error);
        res.status(500).json({ error: 'Failed to submit visit request.' });
    }
});

// Get visit requests for a farmer
app.get('/api/visits/farmer', auth, async (req, res) => {
    if (req.user.role !== 'farmer') {
        return res.status(403).json({ error: 'Access denied. Farmers only.' });
    }
    try {
        const visits = await FarmVisit.find({ farmerId: req.user.id }).sort({ createdAt: -1 });
        res.json(visits);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch visit requests.' });
    }
});

// Get visit requests for a customer
app.get('/api/visits/customer', auth, async (req, res) => {
    if (req.user.role !== 'customer') {
        return res.status(403).json({ error: 'Access denied. Customers only.' });
    }
    try {
        const visits = await FarmVisit.find({ customerId: req.user.id }).sort({ createdAt: -1 });
        res.json(visits);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch your visit requests.' });
    }
});

// Update visit status (Farmer only)
app.patch('/api/visits/:visitId/status', auth, async (req, res) => {
    if (req.user.role !== 'farmer') {
        return res.status(403).json({ error: 'Access denied. Farmers only.' });
    }
    try {
        const { status } = req.body;
        const { visitId } = req.params;

        if (!['accepted', 'rejected'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status provided.' });
        }

        const visit = await FarmVisit.findOneAndUpdate(
            { _id: visitId, farmerId: req.user.id },
            { status },
            { new: true }
        );

        if (!visit) {
            return res.status(404).json({ error: 'Visit not found or you do not have permission to update it.' });
        }
        res.json({ message: `Visit status updated to ${status}.`, visit });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update visit status.' });
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Server Error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
  console.log(`📝 API Documentation:`);
  console.log(`POST http://localhost:${PORT}/api/register - Register a new user`);
  console.log(`POST http://localhost:${PORT}/api/register/customer - Register a new customer`);
  console.log(`POST http://localhost:${PORT}/api/farmers/register - Register a new farmer`);
  console.log(`POST http://localhost:${PORT}/api/login - Login`);
  console.log(`POST http://localhost:${PORT}/api/admin/login - Admin login`);
  console.log(`GET http://localhost:${PORT}/api/admin/dashboard-data - Get admin dashboard data (admin only)`);
  console.log(`GET http://localhost:${PORT}/api/admin/users - Get all users for admin (admin only)`);
  console.log(`GET http://localhost:${PORT}/api/profile - Get user profile (protected)`);
  console.log(`GET http://localhost:${PORT}/api/customer/orders - Get customer orders`);
  console.log(`POST http://localhost:${PORT}/api/orders - Create a new order`);
  console.log(`GET http://localhost:${PORT}/api/orders/:orderId - Get order by ID`);
  console.log(`GET http://localhost:${PORT}/api/orders/customer/:email - Get orders by customer email`);
  console.log(`PATCH http://localhost:${PORT}/api/orders/:orderId/status - Update order status`);
  console.log(`GET http://localhost:${PORT}/api/admin/orders - Get all orders (admin only)`);
  console.log(`GET http://localhost:${PORT}/api/farmer/orders - Get orders for farmer`);
  console.log(`--- PRODUCT ROUTES ---`);
  console.log(`POST http://localhost:${PORT}/api/farmer/products - Add new product (farmer only)`);
  console.log(`GET http://localhost:${PORT}/api/products - Get all products`);
  console.log(`--- FARM VISIT ROUTES ---`);
  console.log(`GET http://localhost:${PORT}/api/farmers - Get all active farmers (protected)`);
  console.log(`POST http://localhost:${PORT}/api/visits/request - Request farm visit (customer only)`);
  console.log(`GET http://localhost:${PORT}/api/visits/farmer - Get farmer visit requests`);
  console.log(`GET http://localhost:${PORT}/api/visits/customer - Get customer visit requests`);
  console.log(`PATCH http://localhost:${PORT}/api/visits/:visitId/status - Update visit status (farmer only)`);
});
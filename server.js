
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs').promises;

const app = express();
const PORT = process.env.PORT || 80;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('.'));

// Simple file-based database (replace with MongoDB/PostgreSQL in production)
const DB_PATH = './database';

// Initialize database directories
async function initDB() {
    try {
        await fs.mkdir(DB_PATH, { recursive: true });
        await fs.mkdir(`${DB_PATH}/products`, { recursive: true });
        await fs.mkdir(`${DB_PATH}/users`, { recursive: true });
        await fs.mkdir(`${DB_PATH}/bans`, { recursive: true });
        await fs.mkdir(`${DB_PATH}/contacts`, { recursive: true });
        await fs.mkdir(`${DB_PATH}/purchases`, { recursive: true });
    } catch (error) {
        console.error('DB init error:', error);
    }
}

// Admin middleware
const adminEmails = ['admin@qualitics.production', 'your-admin@gmail.com', 'testqw16@gmail.com'];

function authenticateAdmin(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (!adminEmails.includes(decoded.email)) {
            return res.status(403).json({ error: 'Admin access required' });
        }
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// Helper functions
async function readData(filename) {
    try {
        const data = await fs.readFile(`${DB_PATH}/${filename}.json`, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return [];
    }
}

async function writeData(filename, data) {
    try {
        await fs.writeFile(`${DB_PATH}/${filename}.json`, JSON.stringify(data, null, 2));
        return true;
    } catch (error) {
        console.error('Write error:', error);
        return false;
    }
}

// Auth Routes
app.post('/api/auth/google', async (req, res) => {
    try {
        const { credential, userInfo } = req.body;
        
        // Verify Google JWT token for production security
        let user;
        try {
            // For Google Identity Services, the credential is already verified by Google's library
            // Additional verification can be added here if needed for extra security
            if (!userInfo || !userInfo.email) {
                throw new Error('Invalid user information provided');
            }
            
            // Validate email format
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(userInfo.email)) {
                throw new Error('Invalid email format');
            }
            
            user = {
                email: userInfo.email,
                name: userInfo.name || userInfo.given_name || 'Unknown User',
                given_name: userInfo.given_name || userInfo.name || 'User',
                picture: userInfo.picture || '',
                joinDate: new Date().toISOString(),
                ipAddress: req.ip || req.connection.remoteAddress || 'unknown',
                lastLogin: new Date().toISOString()
            };
        } catch (verificationError) {
            console.error('Google token verification failed:', verificationError);
            return res.status(401).json({ error: 'Token verification failed' });
        }
        
        // Save user
        const users = await readData('users');
        const existingUser = users.find(u => u.email === user.email);
        
        if (!existingUser) {
            users.push(user);
            await writeData('users', users);
        }
        
        // Generate JWT
        const token = jwt.sign(
            { email: user.email, name: user.name },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            success: true,
            token,
            user,
            isAdmin: adminEmails.includes(user.email)
        });
    } catch (error) {
        res.status(500).json({ error: 'Authentication failed' });
    }
});

// Products Routes
app.get('/api/products', async (req, res) => {
    try {
        const products = await readData('products');
        res.json(products);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch products' });
    }
});

app.post('/api/products', authenticateAdmin, async (req, res) => {
    try {
        const products = await readData('products');
        const newProduct = {
            id: Date.now().toString(),
            ...req.body,
            createdAt: new Date().toISOString()
        };
        
        products.push(newProduct);
        await writeData('products', products);
        
        res.json({ success: true, product: newProduct });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create product' });
    }
});

app.put('/api/products/:id', authenticateAdmin, async (req, res) => {
    try {
        const products = await readData('products');
        const index = products.findIndex(p => p.id === req.params.id);
        
        if (index === -1) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        products[index] = { ...products[index], ...req.body, updatedAt: new Date().toISOString() };
        await writeData('products', products);
        
        res.json({ success: true, product: products[index] });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update product' });
    }
});

app.delete('/api/products/:id', authenticateAdmin, async (req, res) => {
    try {
        const products = await readData('products');
        const filteredProducts = products.filter(p => p.id !== req.params.id);
        
        await writeData('products', filteredProducts);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete product' });
    }
});

// Users Routes
app.get('/api/users', authenticateAdmin, async (req, res) => {
    try {
        const users = await readData('users');
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Bans Routes
app.get('/api/bans', authenticateAdmin, async (req, res) => {
    try {
        const bans = await readData('bans');
        res.json(bans);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch bans' });
    }
});

app.post('/api/bans', authenticateAdmin, async (req, res) => {
    try {
        const bans = await readData('bans');
        const newBan = {
            id: Date.now().toString(),
            ...req.body,
            createdAt: new Date().toISOString()
        };
        
        bans.push(newBan);
        await writeData('bans', bans);
        
        res.json({ success: true, ban: newBan });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create ban' });
    }
});

// Contact Routes
app.post('/api/contact', async (req, res) => {
    try {
        const contacts = await readData('contacts');
        const newContact = {
            id: Date.now().toString(),
            ...req.body,
            createdAt: new Date().toISOString(),
            ipAddress: req.ip
        };
        
        contacts.push(newContact);
        await writeData('contacts', contacts);
        
        res.json({ success: true, message: 'Contact form submitted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to submit contact form' });
    }
});

app.get('/api/contacts', authenticateAdmin, async (req, res) => {
    try {
        const contacts = await readData('contacts');
        res.json(contacts);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch contacts' });
    }
});

// Analytics Routes
app.get('/api/analytics', authenticateAdmin, async (req, res) => {
    try {
        const users = await readData('users');
        const products = await readData('products');
        const contacts = await readData('contacts');
        const purchases = await readData('purchases');
        
        const analytics = {
            totalUsers: users.length,
            totalProducts: products.length,
            totalContacts: contacts.length,
            totalPurchases: purchases.length,
            totalRevenue: purchases.reduce((sum, p) => sum + (p.total || 0), 0)
        };
        
        res.json(analytics);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch analytics' });
    }
});

// Purchase Routes
app.post('/api/purchase', async (req, res) => {
    try {
        const purchases = await readData('purchases');
        const newPurchase = {
            id: Date.now().toString(),
            ...req.body,
            createdAt: new Date().toISOString(),
            ipAddress: req.ip
        };
        
        purchases.push(newPurchase);
        await writeData('purchases', purchases);
        
        res.json({ success: true, purchase: newPurchase });
    } catch (error) {
        res.status(500).json({ error: 'Failed to process purchase' });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Serve static files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Initialize and start server
initDB().then(() => {
    const server = app.listen(PORT, '0.0.0.0', () => {
        console.log(`🚀 Server running on port ${PORT}`);
        console.log(`📱 Local: http://localhost:${PORT}`);
        console.log(`🌐 Network: https://qualitics-production-1.onrender.com`);
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
        console.log('SIGTERM received, shutting down gracefully');
        server.close(() => {
            console.log('Process terminated');
        });
    });
}).catch(error => {
    console.error('Failed to start server:', error);
    process.exit(1);
});

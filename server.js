// server.js

// --- IMPORTS ---
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); // Using the real bcryptjs now
const jwt = require('jsonwebtoken'); // Using the real jsonwebtoken now
const cors = require('cors');
require('dotenv').config(); // Loads variables from .env file

// --- INITIALIZATIONS ---
const app = express();
const PORT = process.env.PORT || 5000;

// --- MIDDLEWARE ---
app.use(cors()); 
app.use(express.json()); 

// --- DATABASE CONNECTION (MongoDB Atlas) ---
// The URI is now loaded securely from your .env file
const dbURI = process.env.MONGODB_URI;

// This is no longer commented out. We are connecting for real.
mongoose.connect(dbURI)
  .then(() => console.log('MongoDB connected successfully to Atlas.'))
  .catch(err => console.error('MongoDB connection error:', err));


// --- DATABASE SCHEMA AND MODEL (No changes needed here) ---
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);


// --- API ROUTES ---

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ msg: 'Please enter all fields.' });
        }

        // REAL DATABASE CHECK: Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
             return res.status(400).json({ msg: 'User with this email already exists.' });
        }
        
        // REAL PASSWORD HASHING
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // REAL USER CREATION: Create and save the new user to the database
        const newUser = new User({ name, email, password: hashedPassword });
        const savedUser = await newUser.save();
        
        console.log('User registered and saved to database.');
        res.status(201).json({
            msg: "User registered successfully!",
            user: { id: savedUser._id, name: savedUser.name, email: savedUser.email }
        });

    } catch (error) {
        console.error("Registration Error:", error);
        res.status(500).json({ error: 'Server error during registration.' });
    }
});


/**
 * @route   POST /api/auth/login
 * @desc    Authenticate a user and return a token
 * @access  Public
 */
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ msg: 'Please enter all fields.' });
        }

        // REAL DATABASE LOOKUP: Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid credentials. User not found.' });
        }

        // REAL PASSWORD COMPARISON: Compare provided password with stored hash
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid credentials. Password incorrect.' });
        }

        // REAL TOKEN GENERATION: Generate and sign a JWT
        const token = jwt.sign({ id: user._id, name: user.name }, process.env.JWT_SECRET, { expiresIn: '1h' });
        
        console.log(`User ${user.email} logged in successfully.`);
        res.status(200).json({
            token,
            msg: "Logged in successfully!",
            user: { id: user._id, name: user.name, email: user.email }
        });

    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ error: 'Server error during login.' });
    }
});


// --- START SERVER ---
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

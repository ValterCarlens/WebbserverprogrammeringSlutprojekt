const express = require('express');
const router = express.Router();
const Message = require('../models/Message');
const User = require('../models/User');

// Simple admin auth middleware
const ADMIN_USER = 'myckethemligtusername';
const ADMIN_PASS = 'myckethemligtpassword'; 

function adminAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Basic ')) {
    return res.status(401).send('Unauthorized');
  }
  const base64 = auth.split(' ')[1];
  const [user, pass] = Buffer.from(base64, 'base64').toString().split(':');
  console.log('Admin login attempt:', user, pass);
  if (user === ADMIN_USER && pass === ADMIN_PASS) {
    return next();
  }
  return res.status(401).send('Unauthorized');
}

// Get all messages (public and private)
router.get('/messages', adminAuth, async (req, res) => {
  const messages = await Message.find().sort({ timestamp: 1 });
  res.json(messages);
});

// Delete a message by ID
router.delete('/messages/:id', adminAuth, async (req, res) => {
  await Message.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});

// Delete a user by ID
router.delete('/users/:id', adminAuth, async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  // Optionally delete user's messages
  await Message.deleteMany({ sender: req.params.id });
  res.json({ success: true });
});

module.exports = router; 
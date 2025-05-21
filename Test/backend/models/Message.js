const mongoose = require('mongoose');

const MessageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  recipient: { type: String, default: null }, // null for public chat
  content: { type: String, required: true }, // encrypted
  timestamp: { type: Date, default: Date.now },
  chatType: { type: String, enum: ['public', 'private'], required: true },
});

module.exports = mongoose.model('Message', MessageSchema); 
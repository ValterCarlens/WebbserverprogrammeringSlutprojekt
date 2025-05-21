require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const adminRoutes = require('./routes/admin');
const User = require('./models/User');
const Message = require('./models/Message');
const { encrypt, decrypt } = require('./utils/encryption');

const app = express();
const server = http.createServer(app);

// Add TCP keepalive settings
server.keepAliveTimeout = 60000; // 60 seconds
server.headersTimeout = 65000; // 65 seconds

// Add request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Configure CORS with more specific settings
app.use(cors({
  origin: ['http://localhost:3000', 'http://192.168.1.99:3000', 'http://192.168.1.99:5000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400 // 24 hours
}));

// Configure Helmet with WebSocket support
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: false,
  crossOriginOpenerPolicy: false
}));

app.use(express.json());

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok',
    timestamp: new Date().toISOString(),
    websocket: {
      enabled: true,
      url: `ws://${req.headers.host}/ws`
    }
  });
});

// WebSocket server setup with more robust configuration
const wss = new WebSocket.Server({ 
  server,
  path: '/ws',
  perMessageDeflate: false,
  clientTracking: true,
  maxPayload: 50 * 1024 * 1024, // 50MB max payload
  verifyClient: (info, callback) => {
    console.log('WebSocket handshake request:', {
      origin: info.origin,
      secure: info.secure,
      req: {
        headers: info.req.headers,
        url: info.req.url
      }
    });
    
    // Allow connections from both localhost and the IP address
    const allowedOrigins = ['http://localhost:3000', 'http://192.168.1.99:3000', 'http://192.168.1.99:5000'];
    if (allowedOrigins.includes(info.origin) || info.origin.startsWith('http://192.168.1.99')) {
      console.log('WebSocket connection allowed from origin:', info.origin);
      callback(true);
    } else {
      console.log('WebSocket connection rejected from origin:', info.origin);
      callback(false, 403, 'Forbidden');
    }
  }
});

// Add ping interval to keep connections alive
const PING_INTERVAL = 30000; // 30 seconds
const PONG_TIMEOUT = 10000; // 10 seconds
const pongTimeout = new Map();

wss.on('listening', () => {
  const address = server.address();
  console.log(`WebSocket server is listening on ${address.address}:${address.port}`);
});

// WebSocket server logging
wss.on('error', (error) => {
  console.error('WebSocket server error:', {
    error,
    message: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString()
  });
});

// MongoDB connection
const connectToMongoDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 10000, // Increased timeout to 10s
      socketTimeoutMS: 45000,
      retryWrites: true,
      w: 'majority'
    });
    console.log('MongoDB connected successfully');
  } catch (err) {
    console.error('MongoDB connection error:', {
      message: err.message,
      code: err.code,
      name: err.name,
      stack: err.stack
    });
    console.log('Attempting to reconnect in 5 seconds...');
    setTimeout(connectToMongoDB, 5000);
  }
};

// Initial connection attempt
connectToMongoDB();

// Handle MongoDB connection events
mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('MongoDB disconnected. Attempting to reconnect...');
  setTimeout(connectToMongoDB, 5000);
});

mongoose.connection.on('reconnected', () => {
  console.log('MongoDB reconnected successfully');
});

// In-memory store for online users: { sessionId: { username, ws } }
const onlineUsers = {};

function broadcastUserList() {
  const userList = Object.values(onlineUsers).map(u => u.username);
  const payload = JSON.stringify({ type: 'userList', users: userList });
  Object.values(onlineUsers).forEach(u => {
    if (u.ws.readyState === WebSocket.OPEN) {
      try {
        console.log('About to send userList to', u.username, 'payload:', payload);
        u.ws.send(payload);
        console.log('userList sent to', u.username);
      } catch (err) {
        console.error('Failed to send userList to', u.username, err);
      }
    }
  });
}

function broadcastToAdmins(data) {
  // For now, treat all connections with username 'admin' as admin
  Object.values(onlineUsers).forEach(u => {
    if (u.username === 'admin') {
      const payload = JSON.stringify(data);
      console.log('Sending to admin', u.username, 'payload:', payload);
      u.ws.send(payload);
    }
  });
}

// WebSocket connection handling
wss.on('connection', (ws, req) => {
  console.log('New WebSocket connection attempt:', {
    address: req.socket.remoteAddress,
    headers: req.headers,
    url: req.url,
    timestamp: new Date().toISOString()
  });
  
  ws.isAlive = true;
  
  // Handle pong responses
  ws.on('pong', () => {
    ws.isAlive = true;
    const timeout = pongTimeout.get(ws);
    if (timeout) {
      clearTimeout(timeout);
      pongTimeout.delete(ws);
    }
  });

  // Send initial connection confirmation
  try {
    ws.send(JSON.stringify({ type: 'connection', status: 'connected' }));
  } catch (error) {
    console.error('Failed to send connection confirmation:', error);
  }
  
  let username = null;
  let sessionId = null;

  // Set up ping interval for this connection
  const pingInterval = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.ping();
        // Set timeout for pong response
        const timeout = setTimeout(() => {
          console.log('Pong timeout, terminating connection');
          clearInterval(pingInterval);
          ws.terminate();
        }, PONG_TIMEOUT);
        pongTimeout.set(ws, timeout);
      } catch (error) {
        console.error('Failed to send ping:', error);
        clearInterval(pingInterval);
        ws.terminate();
      }
    } else {
      clearInterval(pingInterval);
    }
  }, PING_INTERVAL);

  // Clean up on close
  ws.on('close', () => {
    clearInterval(pingInterval);
    const timeout = pongTimeout.get(ws);
    if (timeout) {
      clearTimeout(timeout);
      pongTimeout.delete(ws);
    }
  });

  ws.on('message', async (message) => {
    console.log('Raw WebSocket message received:', message);
    try {
      // Convert Buffer to string if necessary
      const msgString = Buffer.isBuffer(message) ? message.toString('utf8') : message;
      const data = JSON.parse(msgString);
      console.log('Received WebSocket message:', data);

      if (data.type === 'join') {
        username = data.username;
        sessionId = data.sessionId;
        console.log('User joined:', { username, sessionId });
        // Warn if sessionId is already in use
        if (onlineUsers[sessionId]) {
          console.warn('WARNING: sessionId collision detected! Overwriting existing user:', sessionId, onlineUsers[sessionId]);
        }
        // Store user in online users
        onlineUsers[sessionId] = { username, ws };
        console.log('Added to onlineUsers:', Object.keys(onlineUsers));
        // Send confirmation of successful join
        try {
          const joinPayload = JSON.stringify({ 
            type: 'join', 
            status: 'success',
            username,
            sessionId
          });
          console.log('About to send join confirmation:', joinPayload);
          ws.send(joinPayload);
          console.log('Join confirmation sent successfully');
        } catch (err) {
          console.error('Failed to send join confirmation:', err);
        }
        // Broadcast user list update
        broadcastUserList();
        // Send system message about user joining
        const joinMsg = { type: 'system', message: `${username} joined the chat.` };
        Object.values(onlineUsers).forEach(u => {
          try {
            if (u.ws.readyState === WebSocket.OPEN) {
              const payload = JSON.stringify(joinMsg);
              console.log('About to send system message to', u.username, 'payload:', payload);
              u.ws.send(payload);
              console.log('System message sent to', u.username);
            }
          } catch (error) {
            console.error('Failed to send join message:', error);
          }
        });
      } else if (data.type === 'publicMessage') {
        // Handle public message
        console.log('Broadcasting message:', data);
        const messageData = {
          type: 'publicMessage',
          sender: username,
          content: data.content,
          timestamp: new Date()
        };
        // Save message to database
        try {
          const encrypted = encrypt(data.content);
          const msgDoc = new Message({ 
            sender: username, 
            content: encrypted, 
            chatType: 'public' 
          });
          await msgDoc.save();
        } catch (error) {
          console.error('Failed to save message:', error);
        }
        // Broadcast to all clients
        wss.clients.forEach((client) => {
          if (client.readyState === WebSocket.OPEN) {
            try {
              const payload = JSON.stringify(messageData);
              console.log('About to broadcast public message to client, payload:', payload);
              client.send(payload);
              console.log('Public message sent to client');
            } catch (error) {
              console.error('Failed to send message to client:', error);
            }
          }
        });
      }
    } catch (error) {
      console.error('Error processing WebSocket message:', error);
      try {
        ws.send(JSON.stringify({ 
          type: 'error', 
          message: 'Failed to process message' 
        }));
      } catch (sendError) {
        console.error('Failed to send error message:', sendError);
      }
    }
  });

  ws.on('close', (code, reason) => {
    console.log('WebSocket closed:', { code, reason });
    // Remove user from onlineUsers
    if (sessionId && onlineUsers[sessionId] && onlineUsers[sessionId].ws === ws) {
      delete onlineUsers[sessionId];
      console.log('Removed from onlineUsers:', sessionId, 'Current users:', Object.keys(onlineUsers));
      broadcastUserList();
    } else {
      console.log('No matching sessionId found for cleanup or ws mismatch:', sessionId);
    }
  });

  ws.on('error', (err) => {
    console.error('WebSocket error:', err);
  });
});

app.use('/api/admin', adminRoutes);

// Fetch public chat history
app.get('/api/messages/public', async (req, res) => {
  try {
    // Check if MongoDB is connected
    if (mongoose.connection.readyState !== 1) {
      console.error('MongoDB not connected. Current state:', mongoose.connection.readyState);
      return res.status(503).json({ 
        error: 'Database temporarily unavailable',
        details: 'MongoDB connection is not established'
      });
    }

    const Message = require('./models/Message');
    const { decrypt } = require('./utils/encryption');
    
    const messages = await Message.find({ chatType: 'public' }).sort({ timestamp: 1 });
    console.log('Found messages:', messages.length);
    
    const result = messages.map(m => ({
      sender: m.sender,
      content: decrypt(m.content),
      timestamp: m.timestamp
    }));
    
    res.json(result);
  } catch (error) {
    console.error('Error fetching public messages:', {
      message: error.message,
      stack: error.stack,
      code: error.code
    });
    
    res.status(500).json({ 
      error: 'Failed to fetch messages',
      details: error.message,
      code: error.code
    });
  }
});

// Fetch private chat history between two users
app.get('/api/messages/private/:user1/:user2', async (req, res) => {
  const Message = require('./models/Message');
  const { decrypt } = require('./utils/encryption');
  const { user1, user2 } = req.params;
  const messages = await Message.find({
    chatType: 'private',
    $or: [
      { sender: user1, recipient: user2 },
      { sender: user2, recipient: user1 }
    ]
  }).sort({ timestamp: 1 });
  const result = messages.map(m => ({
    sender: m.sender,
    recipient: m.recipient,
    content: decrypt(m.content),
    timestamp: m.timestamp
  }));
  res.json(result);
});

const PORT = process.env.PORT || 5000;
const HOST = '192.168.1.99';

// Add detailed server startup logging
server.on('listening', () => {
  const address = server.address();
  console.log('Server listening details:', {
    address: address.address,
    port: address.port,
    family: address.family,
    timestamp: new Date().toISOString()
  });
});

server.on('error', (error) => {
  console.error('Server error:', {
    error: error.message,
    code: error.code,
    timestamp: new Date().toISOString()
  });
});

// Start the server with specific options
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log('You can connect using:');
  console.log('- Local: http://localhost:5000');
  console.log(`- Network: http://${HOST}:5000 (Wi-Fi)`);
  console.log(`- WebSocket: ws://${HOST}:5000/ws`);
  
  // Log all network interfaces
  const networkInterfaces = require('os').networkInterfaces();
  console.log('Available network interfaces:', networkInterfaces);
}); 
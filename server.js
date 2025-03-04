const express = require('express');
const http = require('http');
const socketIo = require('socket.io');

// App setup
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Serve static files from "public" directory (optional)
app.use(express.static('public'));

// Store connected users
const users = {};

// Socket.io connection handling
io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);
  
  // Handle user joining
  socket.on('join', (username) => {
    users[socket.id] = username;
    console.log(`${username} joined the chat`);
    
    // Broadcast to all clients that a new user joined
    io.emit('message', {
      user: 'Server',
      text: `${username} has joined the chat`,
      time: new Date().toLocaleTimeString()
    });
    
    // Send updated user list to all clients
    io.emit('userList', Object.values(users));
  });
  
  // Handle chat messages
  socket.on('message', (message) => {
    const username = users[socket.id] || 'Anonymous';
    const messageData = {
      user: username,
      text: message.text,
      time: new Date().toLocaleTimeString()
    };
    
    console.log(`${username}: ${message.text}`);
    
    if (message.recipient) {
      // DM: Send to the specific recipient
      const recipientSocketId = Object.keys(users).find(key => users[key] === message.recipient);
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('message', messageData);
      }
      // Also send the message back to the sender
      socket.emit('message', messageData);
    } else {
      // Broadcast the message to all connected clients
      io.emit('message', messageData);
    }
  });
  
  // Handle disconnections
  socket.on('disconnect', () => {
    const username = users[socket.id];
    if (username) {
      console.log(`${username} left the chat`);
      
      // Broadcast to all clients that a user left
      io.emit('message', {
        user: 'Server',
        text: `${username} has left the chat`,
        time: new Date().toLocaleTimeString()
      });
      
      // Remove user from users object
      delete users[socket.id];
      
      // Send updated user list to all clients
      io.emit('userList', Object.values(users));
    }
  });
});

// Server start
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
import express from 'express';
import { createServer } from 'http';
import { WebSocketServer, WebSocket } from 'ws';

// Create Express app and HTTP server
const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server });

const PORT = 3000;

// Serve static files from the public folder
app.use(express.static('public'));

// Store connected clients: username -> WebSocket connection
const clients = new Map<string, WebSocket>();

// Handle WebSocket connections
wss.on('connection', (ws) => {
  let username = '';

  console.log('New client connected');

  // Handle incoming messages
  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data.toString());

      // Message type: register — client identifies itself with a username
      if (message.type === 'register') {
        username = message.username;
        clients.set(username, ws);
        console.log(`${username} registered`);
        ws.send(JSON.stringify({ type: 'info', text: `Registered as ${username}` }));
      }

      // Message type: chat — client sends a message to another user
      if (message.type === 'chat') {
        const recipient = clients.get(message.to);
        if (recipient && recipient.readyState === WebSocket.OPEN) {
          recipient.send(JSON.stringify({
            type: 'chat',
            from: username,
            text: message.text
          }));
        } else {
          ws.send(JSON.stringify({ type: 'info', text: `User ${message.to} is not connected` }));
        }
      }

    } catch (err) {
      console.error('Invalid message format:', err);
    }
  });

  // Handle client disconnect
  ws.on('close', () => {
    clients.delete(username);
    console.log(`${username} disconnected`);
  });
});

// Start server
server.listen(PORT, () => {
  console.log(`Burblit server listening on http://localhost:${PORT}`);
});
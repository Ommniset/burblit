import express from 'express';
import { createServer } from 'http';
import { WebSocketServer, WebSocket } from 'ws';

// Create Express app and HTTP server
// WebSocket server is attached to the same HTTP server to share port 3000
const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server });

const PORT = 3000;

// Serve static files (index.html, sodium.js) from the public folder
app.use(express.static('public'));

// Map of connected clients: username -> WebSocket connection
// The server never stores message content — only connection references
const clients = new Map<string, WebSocket>();

// Handle new WebSocket connections
wss.on('connection', (ws: WebSocket) => {
  let username = '';

  console.log('New client connected');

  // Handle incoming messages from this client
  ws.on('message', (data: Buffer) => {
    try {
      const message = JSON.parse(data.toString());

      // Register: client identifies itself with a username
      // Server stores the WebSocket reference mapped to the username
      if (message.type === 'register') {
        username = message.username;
        clients.set(username, ws);
        console.log(`${username} registered`);
        ws.send(JSON.stringify({ type: 'info', text: `Registered as ${username}` }));
      }

      // Chat: client sends an encrypted blob to a recipient
      // Server looks up the recipient and forwards the blob without reading it
      if (message.type === 'chat') {
        const recipient = clients.get(message.to);
        if (recipient && recipient.readyState === WebSocket.OPEN) {
          recipient.send(JSON.stringify({
            type: 'chat',
            from: username,
            text: message.text  // In future versions this will be an encrypted blob
          }));
        } else {
          ws.send(JSON.stringify({ type: 'info', text: `User ${message.to} is not connected` }));
        }
      }

    } catch (err) {
      console.error('Invalid message format:', err);
    }
  });

  // Remove client from map when they disconnect
  ws.on('close', () => {
    clients.delete(username);
    console.log(`${username} disconnected`);
  });
});

// Start the HTTP + WebSocket server
server.listen(PORT, () => {
  console.log(`Burblit server listening on http://localhost:${PORT}`);
});
import express from 'express';

// Create Express application
const app = express();
const PORT = 3000;

// Basic route to confirm server is running
app.get('/', (req, res) => {
  res.send('Burblit server is running.');
});

// Start the HTTP server
app.listen(PORT, () => {
  console.log(`Burblit server listening on http://localhost:${PORT}`);
});
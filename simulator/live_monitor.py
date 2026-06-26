const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

// Initialize Socket.IO with relaxed CORS boundaries for development environments
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fractal_vault_secure_mesh_key_2026';
const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5000';

// App wide middleware configurations
app.use(cors());
app.use(express.json());

// Serve the clean frontend dashboard files directly out of the public folder
app.use(express.static(path.join(__dirname, 'public')));

// Global API rate limiting scheme to safeguard upstream Flask microservices
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 Minute Evaluation Track Windows
  max: 100,
  message: { error: 'Too many execution requests from this security perimeter token. Access throttled.' }
});

app.use('/check-trust', apiLimiter);

// ─── ENDPOINTS ───────────────────────────────────────────────────────────────

// Provision ephemeral JWT tokens to incoming client simulations
app.get('/token', (req, res) => {
  const payload = { system: 'fractal-vault-mesh', client: 'simulator-node' };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
  return res.json({ token });
});

// Primary validation gateway intercepting incoming requests
app.post('/check-trust', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header profile.' });
  }

  const token = authHeader.split(' ')[1];

  try {
    // Cryptographic signature checking
    jwt.verify(token, JWT_SECRET);

    // Forward the dynamic metrics array directly down to the Flask evaluation processor
    // Uses native AbortSignal timeouts to guarantee gateway resource starvation prevention
    const response = await fetch(`${BACKEND_URL}/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body),
      signal: AbortSignal.timeout(4000) // 4 second hard cap drop rule
    });

    if (!response.ok) {
      throw new Error(`Upstream Engine structural failure returned status code: ${response.status}`);
    }

    const evaluationResult = await response.json();

    // Map the normalized structural payload array
    const broadcastData = {
      timestamp: new Date().toLocaleTimeString(),
      trust_score: evaluationResult.trust_score,
      decision: evaluationResult.decision,
      status: evaluationResult.decision, // Terminal monitor backwards compatibility mapping
      is_anomaly: evaluationResult.trust_score < 40,
      metrics: {
        failed_login_count: req.body.failed_login_count || 0,
        unusual_location: req.body.unusual_location || false,
        unknown_device: req.body.unknown_device || false,
        high_request_rate: req.body.high_request_rate || false
      }
    };

    // Broadcast down the pipeline to BOTH listeners simultaneously
    io.emit('trust_evaluation', broadcastData);
    io.emit('trust_event', broadcastData);

    return res.json(evaluationResult);

  } catch (err) {
    if (err.name === 'TimeoutError') {
      return res.status(504).json({ error: 'Upstream Trust Engine timeout threshold exceeded.' });
    }
    return res.status(403).json({ error: 'Invalid or expired secure infrastructure token verification trace.' });
  }
});

// Fallback entry handling routing anomalies cleanly straight into the Dashboard interface
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── APPLICATION INITIALIZATION ──────────────────────────────────────────────

io.on('connection', (socket) => {
  console.log(`[SOCKET] Active trace context listener pipeline secured: ${socket.id}`);
  
  socket.on('disconnect', () => {
    console.log(`[SOCKET] Trace stream connection context dropped: ${socket.id}`);
  });
});

server.listen(PORT, () => {
  console.log(`\x1b[36m%s\x1b[0m`, `[GATEWAY] Zero Trust Matrix initialized safely on port: ${PORT}`);
});

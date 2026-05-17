/*const express = require("express");
const jwt = require("jsonwebtoken");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
app.use(express.json());

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*"
  }
});

const JWT_SECRET = "fractal-vault-secret-key";

function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json({
      error: "No token provided"
    });
  }

  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      error: "Invalid token format"
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({
      error: "Invalid or expired token"
    });
  }
}

app.get("/", (req, res) => {
  res.send("Fractal Vault Gateway Running");
});

app.get("/token", (req, res) => {
  const token = jwt.sign(
    {
      user: "demo-user",
      role: "tester"
    },
    JWT_SECRET,
    {
      expiresIn: "1h"
    }
  );

  res.json({
    token
  });
});

app.post("/check-trust", verifyToken, async (req, res) => {
  try {
    const response = await fetch(
      "http://127.0.0.1:5000/evaluate-trust",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(req.body)
      }
    );

    const data = await response.json();

    io.emit("trust_event", data);

    res.json({
      gateway: "Node.js Gateway",
      authenticated_user: req.user,
      backend_response: data
    });

  } catch (error) {
    res.status(500).json({
      error: "Python backend not reachable"
    });
  }
});

server.listen(3000, () => {
  console.log("Gateway running on port 3000");
});*/
// gateway-node/index.js
// Fractal Vault — Node.js Gateway
// Secured and debugged version
require("dotenv").config({ path: "C:\\Users\\DELL\\Documents\\GitHub\\.env" });
"use strict";
const express    = require("express");
const jwt        = require("jsonwebtoken");
const http       = require("http");
const { Server } = require("socket.io");
const rateLimit  = require("express-rate-limit");
const cors       = require("cors");

// ─── Environment & Secrets ───────────────────────────────────────────────────

const JWT_SECRET      = process.env.JWT_SECRET;
const INTERNAL_KEY    = process.env.INTERNAL_API_KEY;
const DEMO_USER       = process.env.DEMO_USER;
const DEMO_PASS       = process.env.DEMO_PASS;
const BACKEND_URL     = process.env.BACKEND_URL     || "http://127.0.0.1:5000";
const GATEWAY_PORT    = parseInt(process.env.GATEWAY_PORT || "3000", 10);
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "http://127.0.0.1:5500,http://localhost:5500")
                            .split(",").map(s => s.trim());

// Hard-fail on missing secrets — never start with defaults in production.
const REQUIRED_ENV = { JWT_SECRET, INTERNAL_API_KEY: INTERNAL_KEY, DEMO_USER, DEMO_PASS };
const missing = Object.entries(REQUIRED_ENV)
    .filter(([, v]) => !v)
    .map(([k]) => k);

if (missing.length > 0) {
    console.error("[FATAL] Missing required environment variables:", missing.join(", "));
    console.error("[FATAL] Copy .env to your project root and fill in all values.");
    process.exit(1);
}

// ─── App Setup ───────────────────────────────────────────────────────────────

const app    = express();
const server = http.createServer(app);

// Body size cap: reject payloads > 16 KB before they reach any handler.
app.use(express.json({ limit: "16kb" }));

// ─── CORS ────────────────────────────────────────────────────────────────────
// Strict allowlist — never use origin: "*" on a security gateway.

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (e.g. curl, server-to-server)
        if (!origin || ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error(`CORS: origin '${origin}' not allowed`));
        }
    },
    methods:      ["GET", "POST"],
    allowedHeaders:["Authorization", "Content-Type"],
    credentials:  false
}));

// ─── Socket.IO ───────────────────────────────────────────────────────────────

const io = new Server(server, {
    cors: {
        origin: ALLOWED_ORIGINS,
        methods: ["GET", "POST"]
    }
});

io.on("connection", (socket) => {
    console.log(`[WS] Client connected: ${socket.id} from ${socket.handshake.address}`);
    socket.on("disconnect", () => {
        console.log(`[WS] Client disconnected: ${socket.id}`);
    });
});

// ─── Rate Limiters ───────────────────────────────────────────────────────────

// /token: max 10 attempts per 15 minutes per IP (brute-force protection)
const tokenLimiter = rateLimit({
    windowMs:         15 * 60 * 1000,
    max:              10,
    standardHeaders:  true,
    legacyHeaders:    false,
    message:          { error: "Too many token requests. Try again in 15 minutes." }
});

// /check-trust: max 30 requests per minute per IP
const trustLimiter = rateLimit({
    windowMs:         60 * 1000,
    max:              30,
    standardHeaders:  true,
    legacyHeaders:    false,
    message:          { error: "Rate limit exceeded." }
});

// ─── Middleware: JWT Verification ─────────────────────────────────────────────

function verifyToken(req, res, next) {
    const authHeader = req.headers["authorization"];

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Missing or malformed Authorization header" });
    }

    const token = authHeader.slice(7).trim();
    if (!token) {
        return res.status(401).json({ error: "Empty token" });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET, {
            algorithms: ["HS256"],   // explicit algorithm — prevents alg:none attack
        });
        // Expose only what downstream handlers need
        req.user = { user: decoded.user, role: decoded.role };
        next();
    } catch (err) {
        const msg = err.name === "TokenExpiredError"
            ? "Token has expired"
            : "Invalid token";
        return res.status(403).json({ error: msg });
    }
}

// ─── Middleware: Input Validation ─────────────────────────────────────────────

const ALLOWED_FIELDS = new Set([
    "failed_logins", "unusual_location", "unknown_device", "high_request_rate"
]);

function validateTrustPayload(req, res, next) {
    const body = req.body;

    if (!body || typeof body !== "object" || Array.isArray(body)) {
        return res.status(400).json({ error: "Request body must be a JSON object" });
    }

    const errors = [];

    // Reject unknown fields
    const extra = Object.keys(body).filter(k => !ALLOWED_FIELDS.has(k));
    if (extra.length > 0) {
        errors.push(`Unexpected fields: ${extra.join(", ")}`);
    }

    // failed_logins: integer 0–20
    const fl = body.failed_logins ?? 0;
    if (!Number.isInteger(fl) || fl < 0 || fl > 20) {
        errors.push("failed_logins must be an integer between 0 and 20");
    }

    // Boolean flags
    for (const key of ["unusual_location", "unknown_device", "high_request_rate"]) {
        const val = body[key] ?? false;
        if (typeof val !== "boolean") {
            errors.push(`${key} must be a boolean`);
        }
    }

    if (errors.length > 0) {
        return res.status(422).json({ error: "Validation failed", details: errors });
    }

    // Replace req.body with the sanitised subset only
    req.sanitizedBody = {
        failed_logins:     parseInt(fl, 10),
        unusual_location:  Boolean(body.unusual_location  ?? false),
        unknown_device:    Boolean(body.unknown_device    ?? false),
        high_request_rate: Boolean(body.high_request_rate ?? false),
    };

    next();
}

// ─── Routes ──────────────────────────────────────────────────────────────────

app.get("/", (req, res) => {
    res.json({ service: "Fractal Vault Gateway", status: "running" });
});

app.get("/health", (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
});

/**
 * POST /token
 * Requires valid credentials in the JSON body.
 * Returns a signed JWT valid for 1 hour.
 *
 * Body: { "username": "...", "password": "..." }
 */
app.post("/token", tokenLimiter, (req, res) => {
    const { username, password } = req.body || {};

    if (!username || !password ||
        typeof username !== "string" || typeof password !== "string") {
        return res.status(400).json({ error: "username and password are required" });
    }

    // Constant-time comparison is not critical here since this is a demo system,
    // but we do exact-match only on env-configured credentials.
    if (username !== DEMO_USER || password !== DEMO_PASS) {
        // Same response for wrong user AND wrong password — no enumeration signal.
        return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
        { user: username, role: "tester" },
        JWT_SECRET,
        { algorithm: "HS256", expiresIn: "1h" }
    );

    console.log(`[AUTH] Token issued for user '${username}'`);
    res.json({ token, expires_in: 3600 });
});

/**
 * POST /check-trust
 * Authenticated endpoint. Validates payload, forwards to Flask backend,
 * emits result over WebSocket, returns structured response.
 */
app.post("/check-trust", trustLimiter, verifyToken, validateTrustPayload, async (req, res) => {
    try {
        const backendRes = await fetch(`${BACKEND_URL}/evaluate-trust`, {
            method:  "POST",
            headers: {
                "Content-Type":   "application/json",
                "X-Internal-Key": INTERNAL_KEY          // shared secret — prevents gateway bypass
            },
            body:    JSON.stringify(req.sanitizedBody),
            signal:  AbortSignal.timeout(5000)           // 5-second backend timeout
        });

        if (!backendRes.ok) {
            const errBody = await backendRes.json().catch(() => ({}));
            console.error(`[BACKEND] Non-OK response: ${backendRes.status}`, errBody);
            return res.status(502).json({
                error: "Backend returned an error",
                detail: errBody
            });
        }

        const data = await backendRes.json();

        // Broadcast to all connected WebSocket clients (dashboard)
        io.emit("trust_event", {
            ...data,
            timestamp: new Date().toTimeString().slice(0, 8)
        });

        console.log(
            `[TRUST] user=${req.user.user} score=${data.trust_score} ` +
            `status=${data.status} anomaly=${data.is_anomaly}`
        );

        return res.json({
            gateway:          "Fractal Vault Gateway",
            user:             req.user.user,
            backend_response: data
        });

    } catch (err) {
        if (err.name === "TimeoutError" || err.name === "AbortError") {
            console.error("[BACKEND] Request timed out");
            return res.status(504).json({ error: "Backend request timed out" });
        }
        console.error("[BACKEND] Unreachable:", err.message);
        return res.status(502).json({ error: "Python backend not reachable" });
    }
});

// ─── 404 & Global Error Handler ──────────────────────────────────────────────

app.use((req, res) => {
    res.status(404).json({ error: "Not found" });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    console.error("[ERROR]", err.message);
    if (err.message && err.message.startsWith("CORS")) {
        return res.status(403).json({ error: "CORS policy violation" });
    }
    res.status(500).json({ error: "Internal server error" });
});

// ─── Start ───────────────────────────────────────────────────────────────────

server.listen(GATEWAY_PORT, "127.0.0.1", () => {
    console.log(`[GATEWAY] Fractal Vault Gateway running on http://127.0.0.1:${GATEWAY_PORT}`);
    console.log(`[GATEWAY] Backend target: ${BACKEND_URL}`);
    console.log(`[GATEWAY] Allowed origins: ${ALLOWED_ORIGINS.join(", ")}`);
});
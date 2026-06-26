// gateway-node/index.js
// Fractal Vault — Node.js Gateway
// Fully integrated and corrected version

const path = require("path");

// Portably load the environment file from project folder or fall back to system absolute path
const localEnvPath = path.resolve(__dirname, ".env");
require("dotenv").config({
    path: require("fs").existsSync(localEnvPath) ? localEnvPath : "C:\\Users\\DELL\\Documents\\GitHub\\.env"
});

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

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (e.g. curl, container-to-container checks)
        if (!origin || ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error(`CORS: origin '${origin}' not allowed`));
        }
    },
    methods:      ["GET", "POST"],
    allowedHeaders: ["Authorization", "Content-Type"],
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

const tokenLimiter = rateLimit({
    windowMs:         15 * 60 * 1000,
    max:              10,
    standardHeaders:  true,
    legacyHeaders:    false,
    message:          { error: "Too many token requests. Try again in 15 minutes." }
});

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
            algorithms: ["HS256"],   // Explicit algorithm protects from alg:none exploits
        });
        req.user = { user: decoded.user, role: decoded.role };
        next();
    } catch (err) {
        const msg = err.name === "TokenExpiredError" ? "Token has expired" : "Invalid token";
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

    const extra = Object.keys(body).filter(k => !ALLOWED_FIELDS.has(k));
    if (extra.length > 0) {
        errors.push(`Unexpected fields: ${extra.join(", ")}`);
    }

    const fl = body.failed_logins ?? 0;
    if (!Number.isInteger(fl) || fl < 0 || fl > 20) {
        errors.push("failed_logins must be an integer between 0 and 20");
    }

    for (const key of ["unusual_location", "unknown_device", "high_request_rate"]) {
        const val = body[key] ?? false;
        if (typeof val !== "boolean") {
            errors.push(`${key} must be a boolean`);
        }
    }

    if (errors.length > 0) {
        return res.status(422).json({ error: "Validation failed", details: errors });
    }

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

app.post("/token", tokenLimiter, (req, res) => {
    const { username, password } = req.body || {};

    if (!username || !password || typeof username !== "string" || typeof password !== "string") {
        return res.status(400).json({ error: "username and password are required" });
    }

    if (username !== DEMO_USER || password !== DEMO_PASS) {
        return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
        { user: username, role: "tester" },
        { algorithm: "HS256", expiresIn: "1h" }
    );

    console.log(`[AUTH] Token issued for user '${username}'`);
    res.json({ token, expires_in: 3600 });
});

app.post("/check-trust", trustLimiter, verifyToken, validateTrustPayload, async (req, res) => {
    try {
        const backendRes = await fetch(`${BACKEND_URL}/evaluate-trust`, {
            method:  "POST",
            headers: {
                "Content-Type":   "application/json",
                "X-Internal-Key": INTERNAL_KEY
            },
            body:    JSON.stringify(req.sanitizedBody),
            signal:  AbortSignal.timeout(5000) // 5-second circuit-break timeout
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
            user:              req.user.user,
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

app.use((err, req, res, next) => {
    console.error("[ERROR]", err.message);
    if (err.message && err.message.startsWith("CORS")) {
        return res.status(403).json({ error: "CORS policy violation" });
    }
    res.status(500).json({ error: "Internal server error" });
});

// ─── Start ───────────────────────────────────────────────────────────────────

// Host parameter left out deliberately so that it defaults to 0.0.0.0 listening behavior.
server.listen(GATEWAY_PORT, () => {
    console.log(`[GATEWAY] Fractal Vault Gateway running on port ${GATEWAY_PORT}`);
    console.log(`[GATEWAY] Backend target: ${BACKEND_URL}`);
    console.log(`[GATEWAY] Allowed origins: ${ALLOWED_ORIGINS.join(", ")}`);
});

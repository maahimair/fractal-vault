const express = require("express");
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
});
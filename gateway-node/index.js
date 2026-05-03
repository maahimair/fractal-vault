const express = require("express");

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Fractal Vault Gateway Running");
});

app.post("/check-trust", async (req, res) => {
  try {
    const response = await fetch("http://127.0.0.1:5000/evaluate-trust", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(req.body)
    });

    const data = await response.json();

    res.json({
      gateway: "Node.js Gateway",
      backend_response: data
    });
  } catch (error) {
    res.status(500).json({
      error: "Python backend not reachable"
    });
  }
});

app.listen(3000, () => {
  console.log("Gateway running on port 3000");
});
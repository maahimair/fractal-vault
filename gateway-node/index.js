const express = require("express");

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Fractal Vault Gateway Running");
});

app.listen(3000, () => {
  console.log("Gateway running on port 3000");
});
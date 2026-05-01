from flask import Flask, request, jsonify
import random

app = Flask(__name__)

@app.route("/")
def home():
    return "Fractal Vault Backend Running"

@app.route("/evaluate-trust", methods=["POST"])
def evaluate_trust():
    trust_score = random.randint(50, 100)

    return jsonify({
        "trust_score": trust_score,
        "status": "allowed" if trust_score > 70 else "denied"
    })

if __name__ == "__main__":
    app.run(port=5000, debug=True)
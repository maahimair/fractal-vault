from flask import Flask, request, jsonify

app = Flask(__name__)

def calculate_trust_score(data):
    score = 100

    failed_logins = data.get("failed_logins", 0)
    unusual_location = data.get("unusual_location", False)
    unknown_device = data.get("unknown_device", False)
    high_request_rate = data.get("high_request_rate", False)

    score -= failed_logins * 10

    if unusual_location:
        score -= 20

    if unknown_device:
        score -= 25

    if high_request_rate:
        score -= 15

    score = max(0, min(score, 100))
    return score

@app.route("/")
def home():
    return "Fractal Vault Backend Running"

@app.route("/evaluate-trust", methods=["POST"])
def evaluate_trust():
    data = request.json or {}

    trust_score = calculate_trust_score(data)

    if trust_score >= 70:
        status = "allowed"
    elif trust_score >= 40:
        status = "step-up required"
    else:
        status = "denied"

    return jsonify({
        "trust_score": trust_score,
        "status": status,
        "factors_checked": [
            "failed_logins",
            "unusual_location",
            "unknown_device",
            "high_request_rate"
        ]
    })

if __name__ == "__main__":
    app.run(port=5000, debug=True)
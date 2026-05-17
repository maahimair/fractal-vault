"""  from flask import Flask, request, jsonify
import json
from datetime import datetime
from ml_engine import detect_anomaly

app = Flask(__name__)

def save_log(data, trust_score, status):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "input": data,
        "trust_score": trust_score,
        "status": status
    }

    try:
        with open("logs/trust_logs.json", "r") as file:
            logs = json.load(file)
    except:
        logs = []

    logs.append(log_entry)

    with open("logs/trust_logs.json", "w") as file:
        json.dump(logs, file, indent=4)

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
@app.route("/logs", methods=["GET"])
def get_logs():
    try:
        with open("logs/trust_logs.json", "r") as file:
            logs = json.load(file)

        return jsonify({
            "total_logs": len(logs),
            "logs": logs
        })

    except:
        return jsonify({
            "total_logs": 0,
            "logs": []
        })

@app.route("/evaluate-trust", methods=["POST"])
def evaluate_trust():
    data = request.json or {}

    trust_score = calculate_trust_score(data)
    anomaly_result = detect_anomaly(data)

    if anomaly_result["is_anomaly"]:
        trust_score -= 15
        trust_score = max(0, trust_score)

    if trust_score >= 70:
        status = "allowed"
    elif trust_score >= 40:
        status = "step-up required"
    else:
        status = "denied"
    save_log(data, trust_score, status)

    return jsonify({
        "trust_score": trust_score,
        "status": status,
        "is_anomaly": anomaly_result["is_anomaly"],
        "anomaly_score": anomaly_result["anomaly_score"],
        "factors_checked": [
            "failed_logins",
            "unusual_location",
            "unknown_device",
            "high_request_rate"
        ]
    })


if __name__ == "__main__":
    app.run(port=5000, debug=True)"""
# backend-python/app.py
# Fractal Vault — Flask Trust Engine
# Secured and debugged version
from dotenv import load_dotenv
load_dotenv(r"C:\Users\DELL\Documents\GitHub\.env")
import os
import json
import logging
import threading
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from ml_engine import detect_anomaly

# ─── App Initialisation ──────────────────────────────────────────────────────

app = Flask(__name__)

# Max request body: 16 KB. Reject anything larger before it hits your code.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

# ─── CORS ────────────────────────────────────────────────────────────────────
# Only the Node gateway is allowed to call Flask directly.
# In production replace with your actual gateway origin.
ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS", "http://127.0.0.1:3000,http://localhost:3000"
).split(",")

CORS(app, origins=ALLOWED_ORIGINS, methods=["GET", "POST"],
     allow_headers=["Content-Type", "X-Internal-Key"])

# ─── Rate Limiting ───────────────────────────────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri="memory://"
)

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ─── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "logs", "trust_logs.json")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Thread lock: prevents concurrent writes from corrupting trust_logs.json
log_lock = threading.Lock()

# ─── Secrets ─────────────────────────────────────────────────────────────────
INTERNAL_API_KEY = os.environ.get("FLASK_INTERNAL_API_KEY", "")
LOG_API_KEY       = os.environ.get("LOG_API_KEY", "")

if not INTERNAL_API_KEY:
    logger.warning(
        "FLASK_INTERNAL_API_KEY is not set. "
        "All requests to protected endpoints will be rejected."
    )

if not LOG_API_KEY:
    logger.warning(
        "LOG_API_KEY is not set. /logs endpoint will be inaccessible."
    )

# ─── Decorators ──────────────────────────────────────────────────────────────

def require_internal_key(f):
    """
    Verifies the shared secret sent by the Node gateway.
    Prevents anyone who bypasses the gateway from hitting Flask directly.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-Internal-Key", "")
        if not INTERNAL_API_KEY or key != INTERNAL_API_KEY:
            logger.warning(
                "Rejected request — invalid X-Internal-Key from %s",
                request.remote_addr
            )
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return decorated


def require_log_api_key(f):
    """
    Protects the /logs read endpoint with a separate API key.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key", "")
        if not LOG_API_KEY or key != LOG_API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

# ─── Input Validation ────────────────────────────────────────────────────────

ALLOWED_FIELDS = {
    "failed_logins", "unusual_location",
    "unknown_device", "high_request_rate"
}

def validate_input(data):
    """
    Strictly validate and sanitize all incoming fields.
    Returns (sanitized_dict, errors_list).
    Rejects unknown fields to prevent parameter injection.
    """
    errors = []

    # Reject unexpected fields
    extra = set(data.keys()) - ALLOWED_FIELDS
    if extra:
        errors.append(f"Unexpected fields: {sorted(extra)}")
        return None, errors

    # failed_logins: must be non-negative integer, capped at 20
    fl = data.get("failed_logins", 0)
    if not isinstance(fl, int) or isinstance(fl, bool):
        errors.append("failed_logins must be an integer")
    elif fl < 0 or fl > 20:
        errors.append("failed_logins must be between 0 and 20")

    # Boolean flags
    for key in ("unusual_location", "unknown_device", "high_request_rate"):
        val = data.get(key, False)
        if not isinstance(val, bool):
            errors.append(f"{key} must be a boolean (true/false)")

    if errors:
        return None, errors

    sanitized = {
        "failed_logins":    int(fl),
        "unusual_location": bool(data.get("unusual_location", False)),
        "unknown_device":   bool(data.get("unknown_device", False)),
        "high_request_rate":bool(data.get("high_request_rate", False)),
    }
    return sanitized, []

# ─── Trust Scoring ───────────────────────────────────────────────────────────

def calculate_trust_score(data):
    """
    Compute a trust score 0–100 from validated risk factors.

    Penalty table:
      failed_logins       : -10 per login (capped at 20 → max -200, floor at 0)
      unusual_location    : -20
      unknown_device      : -25
      high_request_rate   : -15

    Score is clamped to [0, 100].
    """
    score = 100

    score -= data.get("failed_logins", 0) * 10

    if data.get("unusual_location", False):
        score -= 20

    if data.get("unknown_device", False):
        score -= 25

    if data.get("high_request_rate", False):
        score -= 15

    return max(0, min(100, score))

# ─── Logging ─────────────────────────────────────────────────────────────────

def save_log(data, trust_score, status, is_anomaly, anomaly_score):
    """
    Persist only known, sanitized fields.
    Never logs raw request bodies or caller-supplied arbitrary keys.
    Uses a threading lock to prevent concurrent write corruption.
    """
    log_entry = {
        "timestamp":        datetime.now().isoformat(),
        "failed_logins":    data.get("failed_logins", 0),
        "unusual_location": data.get("unusual_location", False),
        "unknown_device":   data.get("unknown_device", False),
        "high_request_rate":data.get("high_request_rate", False),
        "trust_score":      trust_score,
        "status":           status,
        "is_anomaly":       is_anomaly,
        "anomaly_score":    anomaly_score,
    }

    with log_lock:
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logs = []

        logs.append(log_entry)

        # Rotate: keep the last 10 000 entries on disk
        if len(logs) > 10_000:
            logs = logs[-10_000:]

        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4)

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return jsonify({"service": "Fractal Vault Backend", "status": "running"})


@app.route("/health")
def health():
    """Internal health check used by the gateway."""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


@app.route("/logs", methods=["GET"])
@require_log_api_key
@limiter.limit("10 per minute")
def get_logs():
    """
    Returns stored trust logs.
    Protected by X-API-Key header.
    Supports optional ?limit=N query param (max 1000).
    """
    try:
        limit = int(request.args.get("limit", 100))
        limit = max(1, min(limit, 1000))
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            logs = json.load(f)
        return jsonify({
            "total_logs": len(logs),
            "returned":   min(limit, len(logs)),
            "logs":       logs[-limit:]
        })
    except (FileNotFoundError, json.JSONDecodeError):
        return jsonify({"total_logs": 0, "returned": 0, "logs": []})


@app.route("/evaluate-trust", methods=["POST"])
@require_internal_key
@limiter.limit("60 per minute")
def evaluate_trust():
    """
    Main trust evaluation endpoint.

    Flow:
      1. Enforce Content-Type
      2. Parse and validate JSON body
      3. Calculate rule-based trust score
      4. Run ML anomaly detection
      5. Apply anomaly penalty if flagged
      6. Determine access decision
      7. Persist sanitized log entry
      8. Return decision (anomaly_score withheld from response)
    """
    # 1. Content-Type guard
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    # 2. Parse
    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"error": "Request body is not valid JSON"}), 400

    data, errors = validate_input(body)
    if errors:
        return jsonify({"error": "Validation failed", "details": errors}), 422

    # 3. Rule-based score
    trust_score = calculate_trust_score(data)

    # 4. ML anomaly detection
    try:
        anomaly_result = detect_anomaly(data)
        is_anomaly    = anomaly_result["is_anomaly"]
        anomaly_score = anomaly_result["anomaly_score"]
    except Exception as e:
        logger.error("ML engine error: %s", e, exc_info=True)
        # Fail secure: treat ML failure as anomalous
        is_anomaly    = True
        anomaly_score = 1.0

    # 5. Anomaly penalty
    if is_anomaly:
        trust_score = max(0, trust_score - 15)

    # 6. Decision
    if trust_score >= 70:
        status = "ALLOWED"
    elif trust_score >= 40:
        status = "STEP-UP REQUIRED"
    else:
        status = "DENIED"

    # 7. Log (includes anomaly_score internally, not exposed to caller)
    save_log(data, trust_score, status, is_anomaly, anomaly_score)

    logger.info(
        "Trust eval — score=%d status=%s anomaly=%s ip=%s",
        trust_score, status, is_anomaly, request.remote_addr
    )

    # 8. Response — anomaly_score intentionally omitted to deny
    #    attackers a signal for boundary probing.
    return jsonify({
        "trust_score":     trust_score,
        "status":          status,
        "is_anomaly":      is_anomaly,
        "factors_checked": [
            "failed_logins",
            "unusual_location",
            "unknown_device",
            "high_request_rate"
        ]
    })

# ─── Error Handlers ──────────────────────────────────────────────────────────

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request"}), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(413)
def request_too_large(e):
    return jsonify({"error": "Request body too large (max 16 KB)"}), 413

@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({"error": "Rate limit exceeded. Slow down."}), 429

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error("Unhandled exception: %s", e, exc_info=True)
    return jsonify({"error": "Internal server error"}), 500

# ─── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    if debug_mode:
        logger.warning("Running in DEBUG mode — do NOT use in production")
    app.run(host="127.0.0.1", port=5000, debug=debug_mode) 
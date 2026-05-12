"""import numpy as np
from sklearn.ensemble import IsolationForest

training_data = np.array([
    [0, 0, 0, 0],
    [1, 0, 0, 0],
    [0, 0, 0, 1],
    [1, 1, 0, 0],
    [2, 0, 0, 0],
    [1, 0, 1, 0],
    [2, 1, 0, 0],
    [0, 1, 0, 0],
    [1, 0, 0, 1],
    [2, 0, 1, 0]
])

model = IsolationForest(contamination=0.2, random_state=42)
model.fit(training_data)

def extract_features(data):
    return np.array([[
        data.get("failed_logins", 0),
        int(data.get("unusual_location", False)),
        int(data.get("unknown_device", False)),
        int(data.get("high_request_rate", False))
    ]])

def detect_anomaly(data):
    features = extract_features(data)

    prediction = model.predict(features)[0]
    score = model.decision_function(features)[0]

    is_anomaly = prediction == -1
    anomaly_score = round(float(abs(score)), 4)

    return {
        "is_anomaly": bool(is_anomaly),
        "anomaly_score": anomaly_score
    }"""
# backend-python/ml_engine.py
# Fractal Vault — ML Anomaly Detection Engine
# Secured and debugged version

import os
import logging
import threading

import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

# ─── Paths ───────────────────────────────────────────────────────────────────

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "ml_model.pkl")

# ─── Thread Safety ───────────────────────────────────────────────────────────
# Protects model swap during live retraining.
# sklearn predict() itself is read-safe for concurrent calls,
# but replacing the global reference must be atomic.

model_lock = threading.RLock()

# ─── Training Data ───────────────────────────────────────────────────────────
# Columns: [failed_logins, unusual_location, unknown_device, high_request_rate]
#
# The original 10-row dataset produced near-random scores.
# This synthetic dataset (1000 samples) gives the IsolationForest
# enough density to draw a meaningful decision boundary.
#
# Distribution:
#   60% normal users   → low failed_logins, mostly false flags
#   25% suspicious     → moderate failed_logins, mixed flags
#   15% attackers      → high failed_logins, multiple true flags

def _generate_training_data() -> np.ndarray:
    rng = np.random.default_rng(42)

    n_normal     = 600
    n_suspicious = 250
    n_attack     = 150

    # Normal: 0–1 failed logins, low risk flags
    normal = np.column_stack([
        rng.integers(0, 2, n_normal),                    # failed_logins 0-1
        rng.choice([0, 1], n_normal, p=[0.90, 0.10]),    # unusual_location
        rng.choice([0, 1], n_normal, p=[0.92, 0.08]),    # unknown_device
        rng.choice([0, 1], n_normal, p=[0.95, 0.05]),    # high_request_rate
    ])

    # Suspicious: 2–4 failed logins, elevated risk flags
    suspicious = np.column_stack([
        rng.integers(2, 5, n_suspicious),
        rng.choice([0, 1], n_suspicious, p=[0.50, 0.50]),
        rng.choice([0, 1], n_suspicious, p=[0.55, 0.45]),
        rng.choice([0, 1], n_suspicious, p=[0.60, 0.40]),
    ])

    # Attack: 5–15 failed logins, mostly true risk flags
    attack = np.column_stack([
        rng.integers(5, 16, n_attack),
        rng.choice([0, 1], n_attack, p=[0.20, 0.80]),
        rng.choice([0, 1], n_attack, p=[0.25, 0.75]),
        rng.choice([0, 1], n_attack, p=[0.15, 0.85]),
    ])

    data = np.vstack([normal, suspicious, attack]).astype(float)
    rng.shuffle(data)
    return data


TRAINING_DATA = _generate_training_data()

# ─── Model Init ──────────────────────────────────────────────────────────────

def _train_model() -> IsolationForest:
    """Train a fresh IsolationForest and return it."""
    model = IsolationForest(
        n_estimators=200,       # more trees → more stable scores
        contamination=0.05,     # expect ~5% anomalies in real traffic
        max_features=1.0,
        bootstrap=False,
        random_state=42,
        n_jobs=-1               # use all CPU cores
    )
    model.fit(TRAINING_DATA)
    logger.info("IsolationForest trained on %d samples", len(TRAINING_DATA))
    return model


def _load_or_train() -> IsolationForest:
    """
    Load a persisted model from disk if available,
    otherwise train from scratch and persist it.
    This avoids retraining on every process restart.
    """
    if os.path.exists(MODEL_PATH):
        try:
            loaded = joblib.load(MODEL_PATH)
            logger.info("Loaded ML model from %s", MODEL_PATH)
            return loaded
        except Exception as e:
            logger.warning("Could not load model (%s). Retraining.", e)

    model = _train_model()
    try:
        joblib.dump(model, MODEL_PATH)
        logger.info("Model saved to %s", MODEL_PATH)
    except Exception as e:
        logger.warning("Could not save model: %s", e)
    return model


# Module-level singleton — loaded once at import time.
_model: IsolationForest = _load_or_train()

# ─── Feature Extraction ──────────────────────────────────────────────────────

def _extract_features(data: dict) -> np.ndarray:
    """
    Convert validated request dict to a (1, 4) float numpy array.

    All inputs are already validated by app.py before reaching here,
    but we apply defensive casts anyway to avoid dtype confusion.

    Feature vector: [failed_logins, unusual_location, unknown_device, high_request_rate]
    """
    failed = float(min(int(data.get("failed_logins", 0) or 0), 20))
    loc    = float(bool(data.get("unusual_location",  False)))
    dev    = float(bool(data.get("unknown_device",    False)))
    rate   = float(bool(data.get("high_request_rate", False)))
    return np.array([[failed, loc, dev, rate]], dtype=np.float64)

# ─── Score Normalisation ─────────────────────────────────────────────────────

# IsolationForest decision_function returns values roughly in [-0.5, 0.5]:
#   positive  → normal (far from anomaly boundary)
#   negative  → anomalous (inside contamination region)
#
# We normalise to [0.0, 1.0] where:
#   0.0 = most normal
#   1.0 = most anomalous
#
# Clipping handles the rare cases where scores fall outside [-0.5, 0.5].

_SCORE_MIN = -0.5
_SCORE_MAX =  0.5

def _normalise_score(raw_score: float) -> float:
    clipped = max(_SCORE_MIN, min(_SCORE_MAX, raw_score))
    # Invert: high raw_score (normal) → low anomaly_score
    normalised = (_SCORE_MAX - clipped) / (_SCORE_MAX - _SCORE_MIN)
    return round(float(normalised), 4)

# ─── Public API ──────────────────────────────────────────────────────────────

def detect_anomaly(data: dict) -> dict:
    """
    Run anomaly detection on a validated trust evaluation request.

    Returns:
        {
            "is_anomaly":    bool,   # True if model flags as anomalous
            "anomaly_score": float   # 0.0 (normal) → 1.0 (anomalous)
        }

    Raises:
        This function never raises. Errors are caught and returned as
        is_anomaly=True (fail-secure) so app.py always gets a result.
    """
    try:
        with model_lock:
            features   = _extract_features(data)
            prediction = _model.predict(features)[0]        # 1 = normal, -1 = anomaly
            raw_score  = _model.decision_function(features)[0]

        is_anomaly    = bool(prediction == -1)
        anomaly_score = _normalise_score(raw_score)

        return {
            "is_anomaly":    is_anomaly,
            "anomaly_score": anomaly_score
        }

    except Exception as e:
        logger.error("detect_anomaly failed: %s", e, exc_info=True)
        # Fail secure: unknown state treated as anomalous
        return {
            "is_anomaly":    True,
            "anomaly_score": 1.0
        }


def retrain(new_samples: np.ndarray) -> bool:
    """
    Hot-swap the model with one retrained on new_samples.
    Thread-safe: acquires model_lock before replacing the global.

    Args:
        new_samples: numpy array of shape (N, 4), same feature order
                     as TRAINING_DATA.

    Returns:
        True on success, False on failure.
    """
    global _model
    if new_samples.shape[1] != 4:
        logger.error("retrain: expected 4 features, got %d", new_samples.shape[1])
        return False

    try:
        combined = np.vstack([TRAINING_DATA, new_samples])
        new_model = IsolationForest(
            n_estimators=200,
            contamination=0.05,
            max_features=1.0,
            bootstrap=False,
            random_state=42,
            n_jobs=-1
        )
        new_model.fit(combined)

        with model_lock:
            _model = new_model
            try:
                joblib.dump(_model, MODEL_PATH)
            except Exception as e:
                logger.warning("retrain: model trained but not saved: %s", e)

        logger.info("Model retrained on %d total samples", len(combined))
        return True

    except Exception as e:
        logger.error("retrain failed: %s", e, exc_info=True)
        return False
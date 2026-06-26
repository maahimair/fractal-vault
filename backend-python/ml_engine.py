# backend-python/ml_engine.py
# Fractal Vault — ML Anomaly Detection Engine
# Fully integrated and corrected version

import os
import logging
import threading
import numpy as np

# Defensive fallback check for joblib/sklearn to avoid bricking Flask on startup
try:
    import joblib
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

logger = logging.getLogger(__name__)

# ─── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "ml_model.pkl")

# ─── Thread Safety ───────────────────────────────────────────────────────────
# Protects model swap during live retraining.
model_lock = threading.RLock()

# Global reference for our model instance
_model = None

# ─── Training Data ───────────────────────────────────────────────────────────
# Columns: [failed_logins, unusual_location, unknown_device, high_request_rate]
# High density synthetic dataset (1000 samples) to draw a reliable decision boundary.
def _generate_training_data() -> np.ndarray:
    rng = np.random.default_rng(42)

    n_normal = 600
    n_suspicious = 250
    n_attack = 150

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

# ─── Model Init & Training ───────────────────────────────────────────────────

def _train_model(training_data) -> object:
    if not SKLEARN_AVAILABLE:
        return None
    model = IsolationForest(
        n_estimators=200,       # More trees -> stable scores
        contamination=0.05,     # Expect ~5% anomalies in traffic baseline
        max_features=1.0,
        bootstrap=False,
        random_state=42,
        n_jobs=-1               # Use all CPU cores
    )
    model.fit(training_data)
    logger.info("IsolationForest trained safely on %d samples", len(training_data))
    return model


def init_engine():
    """
    Initializes the ML model safely. Loaded explicitly by app.py on startup 
    to prevent dependency missing conditions from bricking the server process.
    """
    global _model
    if not SKLEARN_AVAILABLE:
        logger.error("scikit-learn or joblib not installed! Running ML in fail-secure mode.")
        return

    with model_lock:
        if os.path.exists(MODEL_PATH):
            try:
                _model = joblib.load(MODEL_PATH)
                logger.info("Loaded ML model successfully from %s", MODEL_PATH)
                return
            except Exception as e:
                logger.warning("Could not load cached model (%s). Re-training from scratch.", e)

        # Retrain if cache missing or broken
        data = _generate_training_data()
        _model = _train_model(data)
        try:
            joblib.dump(_model, MODEL_PATH)
            logger.info("Model saved to %s", MODEL_PATH)
        except Exception as e:
            logger.warning("Could not save model to disk: %s", e)

# ─── Feature Extraction ──────────────────────────────────────────────────────

def _extract_features(data: dict) -> np.ndarray:
    """
    Convert request dict to a (1, 4) float numpy array.
    """
    failed = float(min(int(data.get("failed_logins", 0) or 0), 20))
    loc    = float(bool(data.get("unusual_location",  False)))
    dev    = float(bool(data.get("unknown_device",    False)))
    rate   = float(bool(data.get("high_request_rate", False)))
    return np.array([[failed, loc, dev, rate]], dtype=np.float64)

# ─── Score Normalisation ─────────────────────────────────────────────────────

def _normalise_score(raw_score: float) -> float:
    """
    Normalizes IsolationForest score from rough range [-0.5, 0.5] to absolute [0.0, 1.0]
    0.0 = most normal, 1.0 = highly anomalous
    """
    _SCORE_MIN, _SCORE_MAX = -0.5, 0.5
    clipped = max(_SCORE_MIN, min(_SCORE_MAX, raw_score))
    # Invert so high risk yields a high value
    normalised = (_SCORE_MAX - clipped) / (_SCORE_MAX - _SCORE_MIN)
    return round(float(normalised), 4)

# ─── Public API ──────────────────────────────────────────────────────────────

def detect_anomaly(data: dict) -> dict:
    """
    Run anomaly detection on a validated trust evaluation request.
    Never crashes; falls back secure (anomaly=True) if error states occur.
    """
    global _model
    if not SKLEARN_AVAILABLE or _model is None:
        return {"is_anomaly": True, "anomaly_score": 1.0}

    try:
        with model_lock:
            features   = _extract_features(data)
            prediction = _model.predict(features)[0]  # 1 = normal, -1 = anomaly
            raw_score  = _model.decision_function(features)[0]

        return {
            "is_anomaly": bool(prediction == -1),
            "anomaly_score": _normalise_score(raw_score)
        }

    except Exception as e:
        logger.error("detect_anomaly engine failure: %s", e, exc_info=True)
        return {"is_anomaly": True, "anomaly_score": 1.0}


def retrain(new_samples: np.ndarray) -> bool:
    """
    Hot-swap the model with one retrained on historical plus incoming updates.
    """
    global _model
    if not SKLEARN_AVAILABLE:
        return False
        
    if new_samples.ndim != 2 or new_samples.shape[1] != 4:
        logger.error("retrain: expected 2D array with 4 features, got shape %s", str(new_samples.shape))
        return False

    try:
        training_data = _generate_training_data()
        combined = np.vstack([training_data, new_samples])
        new_model = _train_model(combined)

        if new_model is not None:
            with model_lock:
                _model = new_model
                try:
                    joblib.dump(_model, MODEL_PATH)
                except Exception as e:
                    logger.warning("retrain: model updated in memory but storage failed: %s", e)
            logger.info("Model hot-swapped successfully. Total dataset: %d samples", len(combined))
            return True
        return False

    except Exception as e:
        logger.error("retrain failed: %s", e, exc_info=True)
        return False

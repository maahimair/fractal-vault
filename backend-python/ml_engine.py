import numpy as np
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
    }
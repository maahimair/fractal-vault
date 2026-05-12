""" import requests
import random
import time

TOKEN_URL = "http://127.0.0.1:3000/token"
TRUST_URL = "http://127.0.0.1:3000/check-trust"

token_response = requests.get(TOKEN_URL)
token = token_response.json()["token"]

headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {token}"
}

for i in range(10):
    payload = {
        "failed_logins": random.randint(0, 6),
        "unusual_location": random.choice([True, False]),
        "unknown_device": random.choice([True, False]),
        "high_request_rate": random.choice([True, False])
    }

    response = requests.post(TRUST_URL, json=payload, headers=headers)

    print("Request:", i + 1)
    print("Input:", payload)
    print("Output:", response.json())
    print("-" * 40)

    time.sleep(1) """
# simulator/simulate_requests.py
# Fractal Vault — Request Simulator
# Secured and debugged version

import os
import sys
import time
import random
import json

import requests
from dotenv import load_dotenv

# ─── Config ──────────────────────────────────────────────────────────────────

load_dotenv()

TOKEN_URL = os.environ.get("TOKEN_URL", "http://127.0.0.1:3000/token")
TRUST_URL = os.environ.get("TRUST_URL", "http://127.0.0.1:3000/check-trust")
SIM_USER  = os.environ.get("SIM_USER")
SIM_PASS  = os.environ.get("SIM_PASS")

if not SIM_USER or not SIM_PASS:
    print("[FATAL] SIM_USER and SIM_PASS must be set in your .env file")
    sys.exit(1)

REQUEST_TIMEOUT  = 10   # seconds per HTTP request
REQUESTS_TOTAL   = 20   # total simulation iterations
SLEEP_BETWEEN    = 1.0  # seconds between requests
TOKEN_REFRESH_S  = 3500 # refresh token before 1h expiry (3600 - 100s buffer)

# ─── Traffic Profiles ────────────────────────────────────────────────────────
# Each profile: (weight, failed_logins_range, location_risk, device_risk, rate_risk)
# Weights must sum to 1.0

PROFILES = [
    {
        "name":            "Normal User",
        "weight":          0.55,
        "failed_logins":   (0, 1),
        "unusual_location":[False, False, False, True],   # 25% chance True
        "unknown_device":  [False, False, False, True],
        "high_request_rate":[False, False, False, False, True],  # 20% chance
    },
    {
        "name":            "Suspicious User",
        "weight":          0.30,
        "failed_logins":   (2, 4),
        "unusual_location":[True, True, False, True],
        "unknown_device":  [True, False, True, True],
        "high_request_rate":[True, False, True, False],
    },
    {
        "name":            "Attacker",
        "weight":          0.15,
        "failed_logins":   (5, 15),
        "unusual_location":[True, True, True, False],
        "unknown_device":  [True, True, True, False],
        "high_request_rate":[True, True, True, False],
    },
]

PROFILE_WEIGHTS = [p["weight"] for p in PROFILES]


def build_payload(profile: dict) -> dict:
    return {
        "failed_logins":     random.randint(*profile["failed_logins"]),
        "unusual_location":  random.choice(profile["unusual_location"]),
        "unknown_device":    random.choice(profile["unknown_device"]),
        "high_request_rate": random.choice(profile["high_request_rate"]),
    }

# ─── Auth ─────────────────────────────────────────────────────────────────────

def fetch_token() -> str:
    """Authenticate and return a JWT. Exits on failure."""
    try:
        resp = requests.post(
            TOKEN_URL,
            json={"username": SIM_USER, "password": SIM_PASS},
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        token = resp.json().get("token")
        if not token:
            print("[FATAL] Token response missing 'token' field:", resp.json())
            sys.exit(1)
        print("[AUTH] Token acquired successfully")
        return token
    except requests.exceptions.ConnectionError:
        print(f"[FATAL] Cannot connect to gateway at {TOKEN_URL}")
        print("[FATAL] Make sure the Node.js gateway is running (npm start)")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"[FATAL] Auth failed: {e.response.status_code} {e.response.text}")
        sys.exit(1)
    except Exception as e:
        print(f"[FATAL] Unexpected error fetching token: {e}")
        sys.exit(1)

# ─── Simulation Loop ─────────────────────────────────────────────────────────

def run_simulation():
    token        = fetch_token()
    token_expiry = time.time() + TOKEN_REFRESH_S

    for i in range(1, REQUESTS_TOTAL + 1):

        # Refresh token before expiry
        if time.time() > token_expiry:
            print("[AUTH] Token near expiry — refreshing...")
            token        = fetch_token()
            token_expiry = time.time() + TOKEN_REFRESH_S

        headers = {
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {token}"
        }

        # Select a traffic profile by weight
        profile = random.choices(PROFILES, weights=PROFILE_WEIGHTS, k=1)[0]
        payload = build_payload(profile)

        print(f"\n{'─'*50}")
        print(f"Request {i}/{REQUESTS_TOTAL} — Profile: {profile['name']}")
        print(f"Input:   {json.dumps(payload)}")

        try:
            resp = requests.post(
                TRUST_URL,
                json=payload,
                headers=headers,
                timeout=REQUEST_TIMEOUT
            )

            if resp.status_code == 401:
                print("[AUTH] Token rejected — re-fetching...")
                token        = fetch_token()
                token_expiry = time.time() + TOKEN_REFRESH_S
                headers["Authorization"] = f"Bearer {token}"
                resp = requests.post(TRUST_URL, json=payload,
                                     headers=headers, timeout=REQUEST_TIMEOUT)

            data = resp.json()
            backend = data.get("backend_response", data)

            score   = backend.get("trust_score", "?")
            status  = backend.get("status", "?")
            anomaly = "YES" if backend.get("is_anomaly") else "NO"

            print(f"Score:   {score}")
            print(f"Status:  {status}")
            print(f"Anomaly: {anomaly}")

            if resp.status_code not in (200, 201):
                print(f"[WARN] HTTP {resp.status_code}: {data}")

        except requests.exceptions.Timeout:
            print(f"[ERROR] Request {i} timed out after {REQUEST_TIMEOUT}s")
        except requests.exceptions.ConnectionError:
            print(f"[ERROR] Request {i} — gateway not reachable at {TRUST_URL}")
        except Exception as e:
            print(f"[ERROR] Request {i} failed: {e}")

        time.sleep(SLEEP_BETWEEN)

    print(f"\n{'─'*50}")
    print(f"[DONE] Simulation complete — {REQUESTS_TOTAL} requests sent")


if __name__ == "__main__":
    run_simulation()
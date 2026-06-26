# simulator/simulate_requests.py
# Fractal Vault — Request Simulator
# Fully aligned with Gateway HTTP specifications

import os
import sys
import time
import random
import json
import requests

# ─── Config ──────────────────────────────────────────────────────────────────

# Force direct local routing bypass (skipping .env dependencies completely)
TOKEN_URL = "http://127.0.0.1:3000/token"
TRUST_URL = "http://127.0.0.1:3000/check-trust"
SIM_USER  = "admin"
SIM_PASS  = "fractal_vault_secure_password_2026"

REQUEST_TIMEOUT  = 10   # seconds per HTTP request
REQUESTS_TOTAL   = 50   # bumped to 50 for realistic dashboard streams
SLEEP_BETWEEN    = 1.0  # seconds between requests
TOKEN_REFRESH_S  = 3500 # refresh token before 1h expiry

# ─── Traffic Profiles ────────────────────────────────────────────────────────
# Weights define the generation likelihood matrix distribution
PROFILES = [
    {
        "name":             "Normal User",
        "weight":          0.55,
        "failed_logins":   (0, 1),
        "unusual_location":[False, False, False, True],   # 25% chance True
        "unknown_device":  [False, False, False, True],
        "high_request_rate":[False, False, False, False, True],  # 20% chance
    },
    {
        "name":             "Suspicious User",
        "weight":          0.30,
        "failed_logins":   (2, 4),
        "unusual_location":[True, True, False, True],
        "unknown_device":  [True, False, True, True],
        "high_request_rate":[True, False, True, False],
    },
    {
        "name":             "Attacker",
        "weight":          0.15,
        "failed_logins":   (5, 12),
        "unusual_location":[True, True, True, False],
        "unknown_device":  [True, True, True, False],
        "high_request_rate":[True, True, True, False],
    },
]

PROFILE_WEIGHTS = [p["weight"] for p in PROFILES]


def build_payload(profile: dict) -> dict:
    # Key names updated to match the gateway input schema validation fields exactly
    return {
        "failed_logins":     random.randint(*profile["failed_logins"]),
        "unusual_location":   random.choice(profile["unusual_location"]),
        "unknown_device":     random.choice(profile["unknown_device"]),
        "high_request_rate":  random.choice(profile["high_request_rate"]),
    }

# ─── Auth ─────────────────────────────────────────────────────────────────────

def fetch_token() -> str:
    """Authenticate via POST request matching the Gateway API definition."""
    try:
        # Changed to requests.post with explicit credentials dictionary mapping
        resp = requests.post(
            TOKEN_URL, 
            json={"username": SIM_USER, "password": SIM_PASS}, 
            headers={"Content-Type": "application/json"},
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
        print("[FATAL] Make sure the Node.js gateway is running (npm run dev)")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"[FATAL] Auth failed: {e.response.status_code} | Msg: {e.response.text}")
        sys.exit(1)
    except Exception as e:
        print(f"[FATAL] Unexpected error fetching token: {e}")
        sys.exit(1)

# ─── Simulation Loop ─────────────────────────────────────────────────────────

def run_simulation():
    token        = fetch_token()
    token_expiry = time.time() + TOKEN_REFRESH_S

    print(f"\n[START] Beginning Zero Trust profile simulation pipeline...")

    for i in range(1, REQUESTS_TOTAL + 1):

        # Refresh token prior to expiration track window
        if time.time() > token_expiry:
            print("[AUTH] Token near expiry — refreshing...")
            token        = fetch_token()
            token_expiry = time.time() + TOKEN_REFRESH_S

        headers = {
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {token}"
        }

        # Select a traffic profile by distribution weight
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
                print("[AUTH] Token rejected — re-fetching live token signature...")
                token        = fetch_token()
                token_expiry = time.time() + TOKEN_REFRESH_S
                headers["Authorization"] = f"Bearer {token}"
                resp = requests.post(TRUST_URL, json=payload, headers=headers, timeout=REQUEST_TIMEOUT)

            data = resp.json()
            
            # Extract nested fields safely from gateway response envelope structure
            backend_data = data.get("backend_response", {})
            score    = backend_data.get("trust_score", "?")
            decision = backend_data.get("status", "?")

            print(f"Score:    {score}/100")
            print(f"Decision: {decision}")

            if resp.status_code not in (200, 201):
                print(f"[WARN] Unexpected Perimeter Status Code {resp.status_code}: {data}")

        except requests.exceptions.Timeout:
            print(f"[ERROR] Request {i} timed out after {REQUEST_TIMEOUT}s")
        except requests.exceptions.ConnectionError:
            print(f"[ERROR] Request {i} — gateway not reachable at {TRUST_URL}")
        except Exception as e:
            print(f"[ERROR] Request {i} failed unexpectedly: {e}")

        time.sleep(SLEEP_BETWEEN)

    print(f"\n{'─'*50}")
    print(f"[DONE] Simulation complete — {REQUESTS_TOTAL} requests successfully dispatched.")


if __name__ == "__main__":
    run_simulation()
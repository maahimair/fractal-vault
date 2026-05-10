import requests
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

    time.sleep(1)
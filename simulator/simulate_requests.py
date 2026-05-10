import requests
import random
import time

URL = "http://127.0.0.1:3000/check-trust"

for i in range(10):
    payload = {
        "failed_logins": random.randint(0, 6),
        "unusual_location": random.choice([True, False]),
        "unknown_device": random.choice([True, False]),
        "high_request_rate": random.choice([True, False])
    }

    response = requests.post(URL, json=payload)

    print("Request:", i + 1)
    print("Input:", payload)
    print("Output:", response.json())
    print("-" * 40)

    time.sleep(1)
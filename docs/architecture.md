# Fractal Vault Architecture

Fractal Vault is a Zero Trust access evaluation system.

## Current Flow

```text
Simulator : Node.js Gateway :Flask Trust Engine : Trust Decision
Components
1. Simulator

Path:

simulator/simulate_requests.py

The simulator creates random login/access behavior and sends it to the Node.js gateway.

It includes:
failed login count
unusual location flag
unknown device flag
high request rate flag
2. Node.js Gateway

Path:

gateway-node/index.js

The gateway is the security entry point.

It handles:

JWT token generation
JWT token verification
request forwarding to the Flask backend

Main endpoints:

GET /token
POST /check-trust
3. Flask Trust Engine

Path:

backend-python/app.py

The Flask backend calculates a trust score from 0 to 100.

Risk factors:

failed logins reduce score by 10 each
unusual location reduces score by 20
unknown device reduces score by 25
high request rate reduces score by 15

Decision logic:

70–100  → allowed
40–69   → step-up required
0–39    → denied
Security Flow
1. Client requests JWT token from gateway
2. Client sends request with Authorization: Bearer token
3. Gateway verifies token
4. Gateway forwards request to Flask backend
5. Flask calculates trust score
6. Gateway returns final response
Current Status

Completed:
Flask trust scoring backend
Node.js gateway
JWT authentication
Simulator
End-to-end request testing

Next planned upgrades:
ML anomaly detection
request logging
dashboard
blockchain audit logging
federated learning simulation


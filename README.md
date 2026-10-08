# Fractal Vault

A Zero Trust access-evaluation gateway. Client telemetry flows through a Node.js
edge gateway into a Python trust engine that returns a single scored access
decision, with a machine-learning anomaly signal layered on top of the
deterministic rules.

```
+--------------------+   HTTPS / JSON   +-------------------------+
|     Simulator      | ----------------> |     Node.js Gateway     |  :3000
|  (Python client)   |   Bearer JWT     |  - JWT auth             |
+--------------------+                   |  - Rate limit + CORS    |
                                       +-------------------------+
                                                    |
                                                    | X-Internal-Key, 5s
                                                    | circuit breaker
                                                    v
                                       +-------------------------+
                       trust_score     |    Flask Trust Engine    |  :5000
                       status  <------- |  - Input validation     |
                       is_anomaly       |  - Rule scoring         |
                                       |  - IsolationForest      |
                                       +-------------------------+
```

## Repository layout

```
fractal-vault/
├── .env.example                 # secret template — copy to .env
├── backend-python/
│   ├── app.py                   # Flask API, auth guards, scoring
│   ├── ml_engine.py             # IsolationForest train/predict/hot-swap
│   └── requirements.txt
├── gateway-node/
│   ├── index.js                 # Express gateway, JWT, rate limits
│   ├── package.json
│   └── public/index.html        # live dashboard (Socket.IO)
├── simulator/
│   └── simulate_requests.py     # traffic generator
├── tests/
│   └── test_trust_engine.py     # 20 tests, no network required
└── docs/architecture.md
```

## Quick start

### 1. Backend

```bash
cd backend-python
python -m venv .venv
.venv/Scripts/activate          # Windows
# source .venv/bin/activate     # macOS / Linux
pip install -r requirements.txt
python app.py                   # http://127.0.0.1:5000
```

On first run `ml_engine.init_engine()` trains an IsolationForest on a seeded
synthetic baseline and caches it to `ml_model.pkl`. That file is gitignored —
delete it any time to force a retrain.

### 2. Gateway

```bash
cd gateway-node
npm install
npm start                       # http://127.0.0.1:3000
```

### 3. Simulator

```bash
cd simulator
python simulate_requests.py
```

## Configuration

Copy `.env.example` to `.env` and fill it in. **`.env` is gitignored and must
never be committed.**

| Variable | Used by | Purpose |
| --- | --- | --- |
| `JWT_SECRET` | gateway | Signs `/token` JWTs |
| `INTERNAL_API_KEY` | gateway | `X-Internal-Key` sent to Flask |
| `FLASK_INTERNAL_API_KEY` | backend | Must equal `INTERNAL_API_KEY` |
| `LOG_API_KEY` | backend | Protects `GET /logs` via `X-API-Key` |
| `DEMO_USER` / `DEMO_PASS` | gateway | Credentials for `POST /token` |
| `SIM_USER` / `SIM_PASS` | simulator | Credentials the simulator logs in with |
| `BACKEND_URL` | gateway | Where Flask is reachable |
| `ALLOWED_ORIGINS` | gateway | Browser origins permitted by CORS |
| `FLASK_ALLOWED_ORIGINS` | backend | Origins permitted to call Flask |
| `FLASK_BIND_HOST` | backend | Defaults to `127.0.0.1` |
| `FLASK_DEBUG` | backend | `true` is local-dev only |

Generate a secret with:

```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

If any gateway variable is missing the process exits immediately with a FATAL
message rather than falling back to a default secret.

## API

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `/health` | none | Liveness probe |
| `POST` | `/token` | demo credentials | Issue a 1h HS256 JWT |
| `POST` | `/check-trust` | `Authorization: Bearer <jwt>` | Evaluate telemetry, returns the decision |
| `GET` | `/logs` | `X-API-Key` | Read persisted trust logs |

`POST /check-trust` accepts exactly these fields and rejects anything else:

```json
{
  "failed_logins": 0,
  "unusual_location": false,
  "unknown_device": false,
  "high_request_rate": false
}
```

`failed_logins` is an integer 0–20; the other three are strict booleans. Unknown
fields are rejected to prevent parameter injection. Responses larger than 16 KB
are refused before they reach application code.

## Scoring

Deterministic rules start at 100 and subtract:

| Signal | Penalty |
| --- | --- |
| `failed_logins` | 10 each (max 20) |
| `unusual_location` | 20 |
| `unknown_device` | 25 |
| `high_request_rate` | 15 |

An IsolationForest anomaly applies a further 15-point penalty. The decision
bands are:

| Score | Status |
| --- | --- |
| ≥ 70 | `ALLOWED` |
| 40–69 | `STEP-UP REQUIRED` |
| < 40 | `DENIED` |

The raw `anomaly_score` is intentionally withheld from the response so callers
cannot map the decision boundary by watching the score drift.

## Tests

```bash
cd backend-python && python -m venv .venv && .venv/Scripts/activate
pip install -r requirements.txt
cd .. && python -m pytest tests -q
```

The suite runs entirely offline against the Flask test client.

## Security notes

- Both services fail **closed**: with no secret configured, protected endpoints
  return 403/401 and the gateway refuses to boot.
- API-key comparison uses constant-time comparison (`hmac.compare_digest` in
  Python, `crypto.timingSafeEqual` in Node) so response timing does not leak
  the secret.
- Flask binds to loopback by default; `FLASK_BIND_HOST=0.0.0.0` is opt-in.
- The gateway sets CSP, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy` and `Cross-Origin-Resource-Policy`.

### Known security debt

- `public/index.html` loads Tailwind from `cdn.tailwindcss.com` and ships inline
  `<style>`/`<script>`, so the CSP must allow `'unsafe-inline'` for scripts and
  styles. Vendoring a compiled stylesheet and pinning a Tailwind version removes
  both the third-party origin and the inline-script allowance.
- Rate limiting uses in-memory storage, so limits reset on restart and are not
  shared across replicas. Use Redis for a multi-instance deployment.
- Trust logs are a plain JSON file rotated at 10 000 entries. Move to an
  append-only store if you need durable audit guarantees.
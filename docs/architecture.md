# Fractal Vault Architecture

Fractal Vault is a Zero Trust access evaluation system built as a two-service
microservice mesh with a Python client simulator.

---

## System Architecture Flow

```text
+-------------------+       REST / JSON       +-------------------------+
|     Simulator     | ----------------------> |     Node.js Gateway     | (Port 3000)
|  (Python client)  |   Authorization: Bearer |  - JWT Auth Engine      |
+-------------------+                         |  - Rate Limiter & CORS  |
                                              |  - Security headers     |
                                              +-------------------------+
                                                           |
                                    Internal REST, X-Internal-Key,
                                    5-second circuit breaker
                                                           v
+-------------------+       JSON Payload      +-------------------------+
|  Trust Decision   | <---------------------- |   Flask Trust Engine    | (Port 5000)
|  (Final Status)   |                         |  - Input validation     |
+-------------------+                         |  - Risk Score Processor |
                                              |  - ML Anomaly Detection |
                                              +-------------------------+

                          Trust logs (rotating JSON, 10 000 entries)
```

---

## System Components

### 1. Simulator

* **Path:** `simulator/simulate_requests.py`
* **Role:** Generates synthetic client traffic across three weighted profiles —
  Normal User (55%), Suspicious User (30%) and Attacker (15%).
* **Credentials:** read from `SIM_USER` / `SIM_PASS`. Nothing is hardcoded.
* **Tracked risk metadata (the exact contract both services validate):**
  * `failed_logins` (Integer, 0–20)
  * `unusual_location` (Boolean)
  * `unknown_device` (Boolean)
  * `high_request_rate` (Boolean)

### 2. Node.js Gateway

* **Path:** `gateway-node/index.js`
* **Port:** `3000`
* **Role:** The Zero Trust perimeter entry point. No client reaches the trust
  engine without passing through it.
* **Core middleware:**
  * `jsonwebtoken` — verifies HS256 signatures with an explicit algorithm list,
    which blocks `alg:none` downgrade attacks.
  * `express-rate-limit` — 10 requests / 15 min on `/token`, 30 / min on
    `/check-trust`.
  * `cors` — explicit origin allowlist.
  * Security headers — CSP, `X-Content-Type-Options`, `X-Frame-Options`,
    `Referrer-Policy`, `Cross-Origin-Resource-Policy`.
* **Body cap:** 16 KB, rejected before reaching any handler.
* **Upstream resilience:** `AbortSignal.timeout(5000)` caps backend calls;
  timeouts surface as `504`, unreachable backend as `502`.
* **Endpoints:**
  * `GET /health` — liveness.
  * `POST /token` — exchanges demo credentials for a 1-hour JWT.
  * `POST /check-trust` — validates claims and payload, proxies to Flask.
  * `GET /*` — SPA fallback, extensionless paths only.

### 3. Flask Trust Engine

* **Path:** `backend-python/app.py`
* **Port:** `5000`, bound to `127.0.0.1` unless `FLASK_BIND_HOST` is overridden.
* **Role:** Validates telemetry and converts it into a single scored decision.
* **Algorithmic penalties (base = 100):**
  * Each failed login: −10 (capped at 20 logins)
  * Unusual location: −20
  * Unknown device: −25
  * High request rate: −15
* **ML anomaly penalty:** a further −15 when the IsolationForest flags the
  request. If scikit-learn is unavailable the engine runs in **fail-secure**
  mode and treats every request as anomalous rather than silently trusting it.
* **Zero Trust enforcement tiers:**
  * **70–100** → `ALLOWED`
  * **40–69** → `STEP-UP REQUIRED` (MFA challenge trigger)
  * **0–39** → `DENIED`
* **Endpoints:**
  * `GET /health` — internal health check.
  * `POST /evaluate-trust` — requires `X-Internal-Key`.
  * `GET /logs` — requires `X-API-Key`.

### 4. ML Engine

* **Path:** `backend-python/ml_engine.py`
* **Model:** `IsolationForest` (200 trees, `contamination=0.05`, fixed seed).
* **Features:** `[failed_logins, unusual_location, unknown_device, high_request_rate]`
* **Baseline:** 1000 seeded synthetic samples across normal / suspicious /
  attack classes.
* **Lifecycle:** `init_engine()` loads `ml_model.pkl` if present, otherwise
  trains and caches it. A corrupt or unloadable cache triggers a clean retrain
  rather than a startup crash.
* **Hot-swap:** `retrain()` replaces the model under an `RLock`, so a live
  retrain cannot race an in-flight prediction.
* **Disclosure:** `anomaly_score` is returned internally and logged, but withheld
  from the HTTP response so callers cannot probe the decision boundary.

---

## Security Lifecycle

1. **Token provisioning** — the client posts credentials to `/token` and
   receives a 1-hour JWT.
2. **Authenticated request** — the client attaches `Authorization: Bearer <JWT>`
   with its device profile to `/check-trust`.
3. **Edge validation** — the gateway verifies the signature, applies rate limits
   and CORS, and strictly validates the payload shape.
4. **Proxy evaluation** — the gateway forwards sanitized data with the
   `X-Internal-Key` shared secret and a 5-second timeout.
5. **Score generation** — Flask applies rule deductions plus the anomaly
   penalty and maps the result to an enforcement tier.
6. **Enforced dispatch** — the gateway relays the decision and broadcasts it to
   the dashboard over Socket.IO.

---

## Known Security Debt

* **Third-party CDN.** `public/index.html` loads Tailwind from
  `cdn.tailwindcss.com` and uses inline `<style>`/`<script>`, so the CSP must
  allow `'unsafe-inline'` for those directives. Vendoring a compiled stylesheet
  and pinning Tailwind removes both the external origin and the inline
  allowance.
* **Rate limiting state.** Limits live in process memory, so they reset on
  restart and are not shared across replicas. Use a Redis store in a
  multi-instance deployment.
* **Trust log storage.** A rotated JSON file is not an audit guarantee. Move to
  an append-only or tamper-evident store if audit integrity matters.
* **Model file integrity.** `ml_model.pkl` is generated locally at startup and
  gitignored. Loading an untrusted pickle executes arbitrary code, so never
  restore one from an external source.
* **Demo authentication.** `/token` compares a single demo credential pair and
  issues an identical `role: "tester"` claim. Replace with real user identity
  and per-role claims before any real deployment.
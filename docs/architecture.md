Here is the raw, clean copy-paste version. There are no conversational intros or outros, so you can copy everything from the box below and paste it directly into your `architecture.md` file.

```markdown
# Fractal Vault Architecture

Fractal Vault is a Zero Trust access evaluation and microservice-mesh system.

---

##  System Architecture Flow

```text
+-------------------+       REST / JSON       +-------------------------+
|     Simulator     | ----------------------> |     Node.js Gateway     | (Port 3000)
|  (Python/Client)  |                         |  - JWT Auth Engine      |
+-------------------+                         |  - Rate Limiter & CORS  |
                                              +-------------------------+
                                                           |
                                                           | Internal REST + Circuit Breaker
                                                           v
+-------------------+       JSON Payload      +-------------------------+
|  Trust Decision   | <---------------------- |   Flask Trust Engine    | (Port 5000)
|  (Final Status)   |                         |  - Risk Score Processor |
+-------------------+                         +-------------------------+

```

---

##  System Components

### 1. Simulator

* **Path:** `simulator/simulate_requests.py`
* **Role:** Simulates distinct client device actors producing dynamic behavioral datasets.
* **Tracked Risk Metadata:**
* `failed_login_count` (Integer)
* `unusual_location` (Boolean)
* `unknown_device` (Boolean)
* `high_request_rate` (Boolean)



### 2. Node.js Gateway

* **Path:** `gateway-node/index.js`
* **Port:** `3000` (Default Entrance)
* **Role:** The Zero Trust perimeter entry point. Enforces traffic filtering before any upstream hits occur.
* **Core Middleware:**
* **`express-rate-limit`**: DDoS mitigative traffic caps.
* **`cors`**: Strict cross-origin request white-listing.
* **`jsonwebtoken`**: Cryptographic parsing and token isolation.


* **Upstream Resiliency:** Features built-in native request timeouts (`AbortSignal`) to prevent backend service starvation.
* **Exposed Endpoints:**
* `GET /token` -> Generates scoped bearer access keys.
* `POST /check-trust` -> Inspects claims, verifies signatures, and proxies downstream checks.



### 3. Flask Trust Engine

* **Path:** `backend-python/app.py`
* **Port:** `5000` (Internal Network Only)
* **Role:** Rule-based algorithmic evaluation engine that parses device risk vectors into an absolute scoring evaluation.
* **Algorithmic Penalties (Base = 100):**
* Each Failed Login: -10
* Unusual Location: -20
* Unknown Device: -25
* High Request Rate: -15


* **Zero Trust Enforcement Tiers:**
* **70 - 100** -> `ALLOWED`
* **40 - 69** -> `STEP-UP REQUIRED` (MFA Challenge Trigger)
* **0 - 39** -> `DENIED` (Immediate Dropped Session)



---

##  Security Lifecycle

1. **Token Provisioning:** Client requests an ephemeral JWT token from the Gateway (`/token`).
2. **Authenticated Request:** Client attaches token via an `Authorization: Bearer <JWT>` header alongside their device profile payload to `/check-trust`.
3. **Edge Validation:** Gateway verifies integrity, handles core rate-limits, and unpacks payload.
4. **Proxy Evaluation:** Gateway safely passes payload to the decoupled Flask Trust Engine.
5. **Score Generation:** Flask assesses dynamic rule deductions and maps out execution tier.
6. **Enforced Dispatch:** Gateway consumes evaluation payload and drops, challenges, or lets the transaction pass.

---

##  Upgrade Roadmap

* [ ] **ML Anomaly Detection:** Replace hardcoded point deductions with an Isolation Forest or Autoencoder model.
* [ ] **Request Logging:** Comprehensive structured JSON logs for auditability.
* [ ] **Dashboard:** Real-time web panel displaying active trust tiers.
* [ ] **Blockchain Audit Logging:** Immutable decentralized ledger auditing for access revocations.
* [ ] **Federated Learning Simulation:** Decentralized risk model training across simulated nodes.

```

```

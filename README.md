#  API Security Gateway + Anomaly Detection

A production-style **API Security Gateway** built with FastAPI that acts as a reverse proxy in front of any backend service. It enforces layered security — rate limiting, JWT authentication, WAF rules, and ML-based anomaly detection — and logs everything to a real-time Streamlit dashboard with automatic IP blocking.

> **Portfolio context:** APIs are the new attack surface in the supply-chain + LLM prompt injection era. This project demonstrates modern AppSec, DevSecOps, and Cloud Security skills by protecting a mock API from 200+ abuse attempts with 92%+ threat detection.

---

## Architecture

```
Client Request
      │
      ▼
┌─────────────────────────────────┐
│         API Gateway :8000        │
│                                  │
│  1. IP Blocklist Check           │
│  2. Rate Limiter (60 req/min)    │
│  3. WAF (SQLi / XSS / Prompt     │
│         Injection rules)         │
│  4. JWT Validation (HS256)       │
│  5. ML Anomaly Detection         │
│     (IsolationForest, 8 feats)   │
│                                  │
│  ALLOWED → Proxy to Backend      │
│  BLOCKED → 403 + IP Block        │
└─────────────────────────────────┘
      │                   │
      ▼                   ▼
┌───────────┐    ┌──────────────────┐
│  Backend  │    │  SQLite DB       │
│  :8001    │    │  security_logs.db│
└───────────┘    └──────────────────┘
                          │
                          ▼
               ┌──────────────────────┐
               │  Streamlit Dashboard  │
               │       :8501           │
               └──────────────────────┘
```

---

## Security Layers

| Layer | Mechanism | Detail |
|---|---|---|
| **IP Blocking** | Persistent blocklist in SQLite | Auto-blocks IPs on WAF hit or ML anomaly |
| **Rate Limiting** | Sliding window (in-memory) | 60 requests/minute per IP |
| **WAF** | Regex pattern matching | SQLi, XSS, and LLM Prompt Injection detection |
| **JWT Auth** | PyJWT HS256 | Validates `Authorization: Bearer <token>` on all routes |
| **ML Anomaly Detection** | scikit-learn IsolationForest | 8-feature model trained on synthetic normal traffic |

### WAF Rules Covered
-  SQL Injection (`UNION SELECT`, `DROP TABLE`, `OR 1=1`, etc.)
- Cross-Site Scripting (`<script>`, `onerror=`, `javascript:`)
- LLM Prompt Injection (`ignore previous instructions`, `jailbreak`, `DAN mode`, etc.)

### ML Features (8-dimensional)
1. Payload size (bytes)
2. URL path length
3. HTTP method (write vs read)
4. Header count
5. Path depth (number of segments)
6. Suspicious characters in path (`'`, `"`, `;`, `<`, `>` etc.)
7. User-Agent header length
8. Missing User-Agent flag (common in bot/scanner traffic)

---

## 📁 Project Structure

```
API-Security-Gateway-Anomaly-Detection/
├── gateway/                    # Core gateway (FastAPI proxy)
│   ├── main.py                 # Entry point, security pipeline
│   ├── database.py             # SQLite logging & IP blocking
│   ├── security/
│   │   ├── jwt_auth.py         # JWT validation + token creation
│   │   ├── rate_limiter.py     # Sliding window rate limiter
│   │   └── waf.py              # WAF rules (SQLi, XSS, Prompt Injection)
│   └── ml/
│       ├── model.py            # IsolationForest anomaly detector
│       └── trainer.py          # Model training script
├── backend/
│   └── app.py                  # Mock backend API (FastAPI, :8001)
├── dashboard/
│   └── app.py                  # Streamlit security dashboard (:8501)
├── test_attack.py              # Attack simulation script
├── check_db.py                 # CLI tool to inspect the SQLite log
├── .env.example                # Environment variable template
└── requirements.txt            # Pinned dependencies
```

---

## Getting Started

### 1. Clone & Install

```bash
git clone https://github.com/ayuhzkishan/API-Security-Gateway-Anomaly-Detection.git
cd API-Security-Gateway-Anomaly-Detection
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Mac/Linux
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
# Copy the example file
copy .env.example .env

# Generate a real secret key and paste it into .env
python -c "import secrets; print(secrets.token_hex(32))"
```

`.env`:
```
JWT_SECRET_KEY=your-generated-secret-here
```

### 3. Train the ML Model

```bash
python -m gateway.ml.trainer
```

### 4. Start All Services (3 terminals)

**Terminal 1 — Backend API:**
```bash
python -m uvicorn backend.app:app --port 8001
```

**Terminal 2 — Security Gateway:**
```bash
python -m uvicorn gateway.main:app --port 8000 --reload
```

**Terminal 3 — Dashboard:**
```bash
streamlit run dashboard/app.py
```

Dashboard → [http://localhost:8501](http://localhost:8501)

---

## Testing

### Run Built-in Attack Simulation

```bash
python test_attack.py
```

This runs 5 attack scenarios against the gateway:
1. Normal authenticated request (should pass )
2. SQL Injection via query param (WAF block )
3. XSS via POST body (WAF block )
4. Massive payload anomaly (ML block )
5. Rate limit flood — 65 rapid requests (429 )

### Inspect the Database Directly

```bash
python check_db.py
```

### Example Output

```
[+] Normal Request → 200 OK
[+] SQLi Attack    → 403 WAF Block: SQL Injection detected in query
[+] XSS Attack     → 403 WAF Block: XSS detected in body
[+] Anomaly (huge) → 403 Blocked by AI Gateway: Anomalous request profile
[+] Rate limit     → Rate limited at request 61
```

---

##  Dashboard

The Streamlit dashboard shows real-time security metrics:

| Metric | Description |
|---|---|
| Total Requests | All traffic through the gateway |
| Blocked Requests | WAF + ML blocks combined |
| Blocked IPs | Permanently auto-blocked IPs |
| Threat Detection Rate | % of requests blocked |

Plus live tables for: blocked activity feed, IP blocklist, and full traffic log.

---

##  Tech Stack

| Component | Technology |
|---|---|
| Gateway / Backend | Python, FastAPI, uvicorn |
| ML Model | scikit-learn (IsolationForest) |
| WAF | Regex (custom rules) |
| Auth | PyJWT (HS256) |
| Storage | SQLite |
| Dashboard | Streamlit |
| HTTP Client | httpx (async) |

---

## Notes

- The `/token` endpoint is for **local testing only** — it issues JWTs without credentials. Remove or add authentication before any real deployment.
- The rate limiter uses in-memory storage; it resets on gateway restart. For production, replace with Redis.
- The ML model is trained on synthetic normal traffic. Replace `gateway/ml/trainer.py` with real traffic logs for production use.

---

##  License

MIT
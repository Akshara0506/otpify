# OTPify — OTP Generation & Verification Microservice

**One line:** A lightweight REST microservice that generates, verifies, tracks and revokes one-time passwords (OTPs), so any project needing signup, login, password-reset or email/phone confirmation can plug it in instead of rewriting OTP logic.

## Why this use case

Almost every student project with user accounts needs "send a code → check the code". Doing it properly is harder than it looks: codes must be random (not `random.randint`), expire, be single-use, limit wrong guesses, and resist brute force. OTPify packages all of that behind a small, framework-agnostic HTTP API that a React, Django, Node or Android project can call. It is not tied to any one project's business logic.

What it handles for you:

| Concern | How OTPify handles it |
|---|---|
| Randomness | `secrets` module (cryptographically secure) |
| Storage safety | Only a salted SHA-256 hash is stored; the plain code is returned once and never saved |
| Expiry | Configurable TTL (30–600 s) |
| Single use | A verified code returns `409` if reused |
| Brute force | Max wrong attempts per code (then `429 OTP_LOCKED`), constant-time comparison |
| Spam | Rate limit: 5 codes per identifier per minute (`429` + `Retry-After` header) |
| Readability | Alphanumeric mode drops look-alike characters (0/O, 1/I/L) |
| Integration | CORS enabled, consistent JSON envelope, `X-Request-ID` for tracing |

## Tech stack

- **Python 3.9+ / Flask 3** — REST API and UI server
- **In-memory store** with a thread lock (no database: OTPs live for minutes, so persistence isn't needed)
- **HTML/CSS/vanilla JS** UI served by Flask (no build step)
- **pytest** (24 tests) and a **Postman collection** (16 requests, 59 assertions)

## Project structure

```
otpify/
├── app.py                 # Flask app: routes, error handlers, headers, logging
├── otp_service.py         # Core logic: generation, hashing, validation, rate limit
├── templates/index.html   # Web UI with live request inspector
├── tests/test_api.py      # Automated tests for every success & error path
├── postman/OTPify.postman_collection.json
├── screenshots/           # Put your submission screenshots here
├── requirements.txt
└── README.md
```

## Run it locally

```bash
# 1. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # macOS / Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the service (listens on port 5000)
python app.py

# 4. Open the UI
#    http://localhost:5000/
```

To use another port: `PORT=5001 python app.py` (macOS/Linux) or `set PORT=5001 && python app.py` (Windows). On macOS, port 5000 is often taken by AirPlay Receiver; use 5001 if you see "Address already in use".

Run the tests: `python -m pytest -v`

## Response format

Every API response uses the same envelope.

Success:
```json
{ "success": true, "data": { ... }, "request_id": "da6fa590e868", "timestamp": "2026-09-24T06:10:11Z" }
```

Error:
```json
{
  "success": false,
  "error": { "code": "VALIDATION_FAILED", "message": "One or more fields are invalid.",
             "details": { "length": "must be between 4 and 10" } },
  "request_id": "c284fb96cb39",
  "timestamp": "2026-09-24T06:10:33Z"
}
```

Every response also carries these headers: `X-Request-ID`, `X-Response-Time`, `X-Service`, `Access-Control-Allow-Origin: *`, and `Cache-Control: no-store` on API routes.

## Endpoints

Base URL: `http://localhost:5000`

| Method | Endpoint | Input | Success | Errors |
|---|---|---|---|---|
| GET | `/api` | — | 200 (lists all endpoints and limits) | — |
| GET | `/api/health` | — | 200 | — |
| POST | `/api/otp/generate` | JSON body | 201 + `Location` header | 400, 415, 429 |
| GET | `/api/otp/quick` | Query params | 201 | 400, 429 |
| POST | `/api/otp/verify` | JSON body | 200 | 400, 401, 404, 409, 410, 415, 429 |
| GET | `/api/otp/{otp_id}` | Path param | 200 | 404 |
| DELETE | `/api/otp/{otp_id}` | Path param | 200 | 404 |
| GET | `/api/stats` | — | 200 | — |

Any unknown route returns `404 ROUTE_NOT_FOUND`, a wrong method returns `405 METHOD_NOT_ALLOWED`, and unexpected server failures return `500 INTERNAL_ERROR`, all as JSON.

### 1. `POST /api/otp/generate`

| Field | Type | Required | Default | Rule |
|---|---|---|---|---|
| `identifier` | string | yes | — | email, phone or user id, max 100 chars |
| `length` | integer | no | 6 | 4–10 |
| `ttl` | integer | no | 120 | seconds, 30–600 |
| `type` | string | no | `numeric` | `numeric` or `alphanumeric` |
| `max_attempts` | integer | no | 3 | 1–10 |

Request:
```bash
curl -X POST http://localhost:5000/api/otp/generate \
  -H "Content-Type: application/json" \
  -d '{"identifier":"student@college.edu","length":6,"ttl":120}'
```

Response `201 Created`:
```json
{
  "success": true,
  "data": {
    "otp_id": "5822dd592b8440539b5f8464a20e6c10",
    "otp": "009417",
    "identifier": "student@college.edu",
    "type": "numeric",
    "length": 6,
    "expires_in_seconds": 119,
    "expires_at": "2026-09-24T06:12:11Z",
    "max_attempts": 3
  },
  "request_id": "da6fa590e868",
  "timestamp": "2026-09-24T06:10:11Z"
}
```

> In production the `otp` would be emailed or texted by the calling app rather than shown to the end user. It's returned here so the calling project can deliver it however it likes.

### 2. `GET /api/otp/quick`

Same fields as above, as query parameters (`identifier` defaults to `browser-demo`). Useful for hitting the service directly from a browser tab.

```
GET http://localhost:5000/api/otp/quick?identifier=demo@x.com&length=8&type=alphanumeric
```

### 3. `POST /api/otp/verify`

| Field | Type | Required |
|---|---|---|
| `otp_id` | string | yes |
| `otp` | string | yes (case-insensitive) |

Request:
```bash
curl -X POST http://localhost:5000/api/otp/verify \
  -H "Content-Type: application/json" \
  -d '{"otp_id":"5822dd592b8440539b5f8464a20e6c10","otp":"009417"}'
```

Response `200 OK`:
```json
{
  "success": true,
  "data": { "verified": true, "otp_id": "5822dd59...", "identifier": "student@college.edu",
            "message": "OTP verified successfully." },
  "request_id": "...", "timestamp": "..."
}
```

Error outcomes:

| Status | `error.code` | When |
|---|---|---|
| 400 | `VALIDATION_FAILED` / `MALFORMED_JSON` | Missing fields or broken JSON |
| 401 | `OTP_INCORRECT` | Wrong code (`details.attempts_remaining` included) |
| 404 | `OTP_NOT_FOUND` | Unknown `otp_id` |
| 409 | `OTP_ALREADY_USED` | Code was already verified |
| 410 | `OTP_EXPIRED` / `OTP_REVOKED` | Past its TTL or revoked |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | `Content-Type` isn't `application/json` |
| 429 | `OTP_LOCKED` | Too many wrong attempts |

### 4. `GET /api/otp/{otp_id}`

Returns status (`pending`, `verified`, `expired`, `locked`, `revoked`), attempts used and remaining, and expiry. It never returns the code itself.

### 5. `DELETE /api/otp/{otp_id}`

Revokes a code (e.g. the user asked for a new one). Returns `200`, or `404` if the id is unknown.

### 6. `GET /api/stats`

Counters: `generated`, `verified`, `failed_attempts`, `rate_limited`, `active`.

## Using it from another project

JavaScript:
```js
const r = await fetch("http://localhost:5000/api/otp/generate", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ identifier: userEmail })
});
const { data } = await r.json();   // send data.otp by email, keep data.otp_id
```

Python:
```python
import requests
d = requests.post("http://localhost:5000/api/otp/generate", json={"identifier": "u@x.com"}).json()["data"]
ok = requests.post("http://localhost:5000/api/otp/verify",
                   json={"otp_id": d["otp_id"], "otp": user_input}).status_code == 200
```

## The web UI

Open `http://localhost:5000/`. It includes:

- **Issue a code:** generates an OTP and shows it on a token-style display with a live countdown.
- **Check a code:** verifies with per-character input boxes (paste works), and looks up status.
- **Try the error cases:** one-click buttons that send deliberately bad requests (400, 401, 404, 405, 415, 429).
- **Request inspector:** every request the page makes, with URL, method, request headers and body, status, response headers and body.
- **Health indicator and live counters** from `/api/health` and `/api/stats`.

## Screenshots

### Step 4 — Server running locally
Run `python app.py` and capture the terminal showing the banner, `Running on http://127.0.0.1:5000` and a few request log lines.

![Server startup](screenshots/01-server-startup.png)

### Step 5 — Connectivity inspection
**Browser:** open the UI, press F12 → **Network** tab → **Fetch/XHR** filter → click **Issue code** → select the `generate` request. Capture the **Headers** tab (Request URL, method, status 201, response headers including `X-Request-ID`) and the **Response** tab.

![Browser network inspect](screenshots/02-browser-network-headers.png)
![Browser network response](screenshots/03-browser-network-response.png)

**curl:**
```bash
curl -v -X POST http://localhost:5000/api/otp/generate -H "Content-Type: application/json" -d "{\"identifier\":\"student@college.edu\"}"
```
(That quoting works on Windows CMD, macOS and Linux.)

![curl -v output](screenshots/04-curl-verbose.png)

### Step 6 — Postman testing
Import `postman/OTPify.postman_collection.json` (Postman → Import). Run the requests in folder **1** first; they save `otp_id` and `otp` into collection variables automatically.

| Screenshot | Request | Expected |
|---|---|---|
| `05-postman-generate-valid.png` | Generate OTP (valid) | 201 Created |
| `06-postman-verify-valid.png` | Verify OTP (valid) | 200 OK |
| `07-postman-invalid-400.png` | Generate – length out of range | 400 VALIDATION_FAILED |
| `08-postman-wrong-code-401.png` | Verify – wrong code | 401 OTP_INCORRECT |
| `09-postman-runner.png` | Collection Runner, whole collection | all tests passing |

![Postman valid](screenshots/05-postman-generate-valid.png)
![Postman verify](screenshots/06-postman-verify-valid.png)
![Postman 400](screenshots/07-postman-invalid-400.png)
![Postman 401](screenshots/08-postman-wrong-code-401.png)
![Postman runner](screenshots/09-postman-runner.png)

## Design notes and limits

- The in-memory store resets when the service restarts, and it works for a single process. To run several instances, swap `OTPStore` for a Redis-backed version with the same methods.
- Finished records are swept 15 minutes after expiry to keep memory bounded.
- `app.run` uses Flask's development server, which is fine for this assignment. For deployment use `gunicorn -w 1 app:app` (one worker, because the store is in memory).

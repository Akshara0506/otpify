"""
OTPify — a reusable One-Time Password microservice.

Any student project that needs "send a code, then check the code"
(signup, login, password reset, email/phone confirmation) can call this
service instead of re-implementing OTP logic.

Run:  python app.py          -> http://localhost:5000
"""
import logging
import os
import time
import uuid

from flask import Flask, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from otp_service import (
    ATTEMPTS_DEFAULT, ATTEMPTS_MAX, ATTEMPTS_MIN, LENGTH_DEFAULT, LENGTH_MAX, LENGTH_MIN,
    OTP_TYPES, RATE_LIMIT_COUNT, RATE_LIMIT_WINDOW, TTL_DEFAULT, TTL_MAX, TTL_MIN,
    OTPError, OTPStore, iso, validate_generate, validate_verify,
)

SERVICE_NAME = "OTPify"
VERSION = "1.0.0"
PORT = int(os.environ.get("PORT", 5000))
STARTED_AT = time.time()

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-7s | %(message)s")
log = logging.getLogger(SERVICE_NAME)

app = Flask(__name__)
app.json.sort_keys = False
store = OTPStore()


# ---- Response envelope -----------------------------------------------------
def ok(data, status=200):
    return jsonify({
        "success": True,
        "data": data,
        "request_id": g.request_id,
        "timestamp": iso(time.time()),
    }), status


def fail(status, code, message, details=None):
    body = {
        "success": False,
        "error": {"code": code, "message": message},
        "request_id": getattr(g, "request_id", None),
        "timestamp": iso(time.time()),
    }
    if details:
        body["error"]["details"] = details
    return jsonify(body), status


def json_body():
    """Enforce Content-Type: application/json and a parseable body."""
    if not request.is_json:
        raise OTPError("Content-Type must be application/json.", 415, "UNSUPPORTED_MEDIA_TYPE")
    data = request.get_json(silent=True)
    if data is None:
        raise OTPError("Request body is not valid JSON.", 400, "MALFORMED_JSON")
    return data


# ---- Request lifecycle: tracing headers + access log -----------------------
@app.before_request
def before():
    g.start = time.perf_counter()
    g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:12]


@app.after_request
def after(resp):
    elapsed = (time.perf_counter() - g.start) * 1000
    resp.headers["X-Request-ID"] = g.request_id
    resp.headers["X-Response-Time"] = f"{elapsed:.2f}ms"
    resp.headers["X-Service"] = f"{SERVICE_NAME}/{VERSION}"
    # CORS so peers' frontends (React, plain JS, etc.) can call this service
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Request-ID"
    resp.headers["Access-Control-Expose-Headers"] = "X-Request-ID, X-Response-Time, X-Service, Retry-After"
    if request.path.startswith("/api"):
        resp.headers["Cache-Control"] = "no-store"  # OTP responses must never be cached
        log.info("%s %s -> %s (%.2fms) id=%s", request.method, request.full_path.rstrip("?"),
                 resp.status_code, elapsed, g.request_id)
    return resp


# ---- Error handlers (always JSON for /api) ----------------------------------
@app.errorhandler(OTPError)
def handle_otp_error(e):
    resp, status = fail(e.status, e.code, e.message, e.details)
    if status == 429 and "retry_after_seconds" in e.details:
        resp.headers["Retry-After"] = str(e.details["retry_after_seconds"])
    return resp, status


@app.errorhandler(HTTPException)
def handle_http_error(e):
    codes = {404: "ROUTE_NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}
    message = e.description
    if e.code == 404:
        message = f"No endpoint at {request.path}. See GET /api for the list of endpoints."
    if e.code == 405:
        message = f"{request.method} is not allowed on {request.path}."
    return fail(e.code, codes.get(e.code, e.name.upper().replace(" ", "_")), message)


@app.errorhandler(Exception)
def handle_unexpected(e):
    log.exception("Unhandled error")
    return fail(500, "INTERNAL_ERROR", "Something went wrong on the server. Check the server logs.")


# ---- UI ----------------------------------------------------------------------
@app.get("/")
def index():
    return render_template("index.html", service=SERVICE_NAME, version=VERSION, port=PORT)


# ---- API ---------------------------------------------------------------------
@app.get("/api")
def api_index():
    """Self-describing endpoint list — handy for peers integrating the service."""
    return ok({
        "service": SERVICE_NAME,
        "version": VERSION,
        "description": "Generate and verify one-time passwords for signup, login and password-reset flows.",
        "endpoints": [
            {"method": "GET", "path": "/api/health", "purpose": "Liveness check"},
            {"method": "POST", "path": "/api/otp/generate", "purpose": "Create an OTP (JSON body)"},
            {"method": "GET", "path": "/api/otp/quick", "purpose": "Create an OTP via query params (browser-friendly)"},
            {"method": "POST", "path": "/api/otp/verify", "purpose": "Check an OTP (single use)"},
            {"method": "GET", "path": "/api/otp/<otp_id>", "purpose": "Status of an OTP (never reveals the code)"},
            {"method": "DELETE", "path": "/api/otp/<otp_id>", "purpose": "Revoke an OTP"},
            {"method": "GET", "path": "/api/stats", "purpose": "Usage counters"},
        ],
        "limits": {
            "length": [LENGTH_MIN, LENGTH_MAX], "ttl_seconds": [TTL_MIN, TTL_MAX],
            "max_attempts": [ATTEMPTS_MIN, ATTEMPTS_MAX], "types": sorted(OTP_TYPES),
            "rate_limit": f"{RATE_LIMIT_COUNT} per identifier per {RATE_LIMIT_WINDOW}s",
        },
    })


@app.get("/api/health")
def health():
    return ok({"status": "UP", "service": SERVICE_NAME, "version": VERSION,
               "uptime_seconds": int(time.time() - STARTED_AT)})


def _generated_payload(record, otp):
    view = record.public_view()
    return {
        "otp_id": record.otp_id,
        "otp": otp,  # in production you'd email/SMS this instead of returning it
        "identifier": record.identifier,
        "type": record.otp_type,
        "length": record.length,
        "expires_in_seconds": view["expires_in_seconds"],
        "expires_at": view["expires_at"],
        "max_attempts": record.max_attempts,
    }


@app.post("/api/otp/generate")
def generate():
    identifier, otp_type, length, ttl, attempts = validate_generate(json_body())
    record, otp = store.generate(identifier, otp_type, length, ttl, attempts)
    resp, status = ok(_generated_payload(record, otp), 201)
    resp.headers["Location"] = f"/api/otp/{record.otp_id}"
    return resp, status


@app.get("/api/otp/quick")
def generate_quick():
    """Same as POST /generate but via query string, so it can be hit from a browser tab."""
    payload = {k: v for k, v in request.args.items()}
    payload.setdefault("identifier", "browser-demo")
    identifier, otp_type, length, ttl, attempts = validate_generate(payload)
    record, otp = store.generate(identifier, otp_type, length, ttl, attempts)
    return ok(_generated_payload(record, otp), 201)


@app.post("/api/otp/verify")
def verify():
    otp_id, otp = validate_verify(json_body())
    record = store.verify(otp_id, otp)
    return ok({"verified": True, "otp_id": record.otp_id, "identifier": record.identifier,
               "message": "OTP verified successfully."})


@app.get("/api/otp/<otp_id>")
def otp_status(otp_id):
    return ok(store.get(otp_id).public_view())


@app.delete("/api/otp/<otp_id>")
def otp_revoke(otp_id):
    record = store.revoke(otp_id)
    return ok({"otp_id": record.otp_id, "status": "revoked", "message": "OTP revoked."})


@app.get("/api/stats")
def stats():
    return ok(store.snapshot())


if __name__ == "__main__":
    banner = "\n".join([
        "=" * 62,
        f"  {SERVICE_NAME} v{VERSION} - OTP generation & verification microservice",
        f"  UI   : http://localhost:{PORT}/",
        f"  API  : http://localhost:{PORT}/api",
        f"  Health check: curl -v http://localhost:{PORT}/api/health",
        "=" * 62,
    ])
    print(banner, flush=True)
    log.info("Starting %s on port %s (PID %s)", SERVICE_NAME, PORT, os.getpid())
    app.run(host="0.0.0.0", port=PORT, debug=False)

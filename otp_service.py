"""
OTPify core logic — generation, storage, verification and input validation.

Kept deliberately free of Flask so it can be unit-tested and reused.
Storage is an in-memory dict guarded by a lock (no database needed:
OTPs are short-lived by nature, so persistence would be a liability).
"""
import hashlib
import hmac
import secrets
import string
import threading
import time
import uuid
from dataclasses import dataclass

# ---- Limits (single place to tune the service) ----------------------------
LENGTH_MIN, LENGTH_MAX, LENGTH_DEFAULT = 4, 10, 6
TTL_MIN, TTL_MAX, TTL_DEFAULT = 30, 600, 120            # seconds
ATTEMPTS_MIN, ATTEMPTS_MAX, ATTEMPTS_DEFAULT = 1, 10, 3
IDENTIFIER_MAX = 100
RATE_LIMIT_COUNT, RATE_LIMIT_WINDOW = 5, 60             # 5 codes / identifier / minute
OTP_TYPES = {
    "numeric": string.digits,
    # ambiguous characters (0/O, 1/I/L) removed so users can read codes easily
    "alphanumeric": "ABCDEFGHJKMNPQRSTUVWXYZ23456789",
}


class OTPError(Exception):
    """Domain error that maps cleanly to an HTTP status + machine-readable code."""

    def __init__(self, message, status=400, code="INVALID_INPUT", details=None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        self.details = details or {}


@dataclass
class OTPRecord:
    otp_id: str
    identifier: str
    otp_type: str
    length: int
    salt: str
    otp_hash: str
    created_at: float
    expires_at: float
    max_attempts: int
    attempts: int = 0
    status: str = "pending"  # pending | verified | locked | revoked (expired is computed)

    def current_status(self, now=None):
        now = now or time.time()
        if self.status == "pending" and now >= self.expires_at:
            return "expired"
        return self.status

    def public_view(self):
        now = time.time()
        return {
            "otp_id": self.otp_id,
            "identifier": self.identifier,
            "type": self.otp_type,
            "length": self.length,
            "status": self.current_status(now),
            "attempts_used": self.attempts,
            "attempts_remaining": max(self.max_attempts - self.attempts, 0),
            "created_at": iso(self.created_at),
            "expires_at": iso(self.expires_at),
            "expires_in_seconds": max(int(self.expires_at - now), 0),
        }


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _hash(otp, salt):
    return hashlib.sha256(f"{salt}:{otp}".encode()).hexdigest()


# ---- Validation helpers ----------------------------------------------------
def _int_field(payload, name, default, lo, hi, errors):
    value = payload.get(name, default)
    if isinstance(value, bool):  # bool is a subclass of int in Python; reject it
        errors[name] = "must be an integer"
        return default
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        value = int(value)
    if not isinstance(value, int):
        errors[name] = "must be an integer"
        return default
    if not lo <= value <= hi:
        errors[name] = f"must be between {lo} and {hi}"
    return value


def validate_generate(payload):
    if not isinstance(payload, dict):
        raise OTPError("Request body must be a JSON object.", 400, "INVALID_BODY")

    errors = {}
    identifier = payload.get("identifier")
    if identifier is None or (isinstance(identifier, str) and not identifier.strip()):
        errors["identifier"] = "is required (e.g. an email, phone number or user id)"
    elif not isinstance(identifier, str):
        errors["identifier"] = "must be a string"
    elif len(identifier) > IDENTIFIER_MAX:
        errors["identifier"] = f"must be at most {IDENTIFIER_MAX} characters"

    otp_type = payload.get("type", "numeric")
    if otp_type not in OTP_TYPES:
        errors["type"] = f"must be one of {sorted(OTP_TYPES)}"

    length = _int_field(payload, "length", LENGTH_DEFAULT, LENGTH_MIN, LENGTH_MAX, errors)
    ttl = _int_field(payload, "ttl", TTL_DEFAULT, TTL_MIN, TTL_MAX, errors)
    attempts = _int_field(payload, "max_attempts", ATTEMPTS_DEFAULT, ATTEMPTS_MIN, ATTEMPTS_MAX, errors)

    if errors:
        raise OTPError("One or more fields are invalid.", 400, "VALIDATION_FAILED", errors)
    return identifier.strip(), otp_type, length, ttl, attempts


def validate_verify(payload):
    if not isinstance(payload, dict):
        raise OTPError("Request body must be a JSON object.", 400, "INVALID_BODY")
    errors = {}
    otp_id, otp = payload.get("otp_id"), payload.get("otp")
    if not isinstance(otp_id, str) or not otp_id.strip():
        errors["otp_id"] = "is required and must be a string"
    if isinstance(otp, int) and not isinstance(otp, bool):
        otp = str(otp)
    if not isinstance(otp, str) or not otp.strip():
        errors["otp"] = "is required and must be a string"
    elif len(otp.strip()) > LENGTH_MAX:
        errors["otp"] = f"must be at most {LENGTH_MAX} characters"
    if errors:
        raise OTPError("One or more fields are invalid.", 400, "VALIDATION_FAILED", errors)
    return otp_id.strip(), otp.strip().upper()


# ---- Store -----------------------------------------------------------------
class OTPStore:
    def __init__(self, retention_seconds=900):
        self._records = {}
        self._rate = {}
        self._lock = threading.Lock()
        self._retention = retention_seconds
        self.stats = {"generated": 0, "verified": 0, "failed_attempts": 0, "rate_limited": 0}

    # Remove records that finished long ago so memory stays bounded.
    def _sweep(self, now):
        dead = [k for k, r in self._records.items() if now - r.expires_at > self._retention]
        for k in dead:
            del self._records[k]

    def _check_rate(self, identifier, now):
        hits = [t for t in self._rate.get(identifier, []) if now - t < RATE_LIMIT_WINDOW]
        if len(hits) >= RATE_LIMIT_COUNT:
            retry = int(RATE_LIMIT_WINDOW - (now - hits[0])) + 1
            self.stats["rate_limited"] += 1
            raise OTPError(
                f"Too many OTPs requested for this identifier. Try again in {retry}s.",
                429, "RATE_LIMITED", {"retry_after_seconds": retry},
            )
        hits.append(now)
        self._rate[identifier] = hits

    def generate(self, identifier, otp_type, length, ttl, max_attempts):
        now = time.time()
        with self._lock:
            self._sweep(now)
            self._check_rate(identifier, now)
            alphabet = OTP_TYPES[otp_type]
            otp = "".join(secrets.choice(alphabet) for _ in range(length))  # CSPRNG
            salt = secrets.token_hex(8)
            record = OTPRecord(
                otp_id=uuid.uuid4().hex, identifier=identifier, otp_type=otp_type,
                length=length, salt=salt, otp_hash=_hash(otp, salt),
                created_at=now, expires_at=now + ttl, max_attempts=max_attempts,
            )
            self._records[record.otp_id] = record
            self.stats["generated"] += 1
        # The plain OTP is returned once and never stored — only its salted hash is kept.
        return record, otp

    def get(self, otp_id):
        with self._lock:
            record = self._records.get(otp_id)
        if record is None:
            raise OTPError("No OTP exists with this otp_id.", 404, "OTP_NOT_FOUND", {"otp_id": otp_id})
        return record

    def verify(self, otp_id, otp):
        with self._lock:
            record = self._records.get(otp_id)
            if record is None:
                raise OTPError("No OTP exists with this otp_id.", 404, "OTP_NOT_FOUND", {"otp_id": otp_id})

            status = record.current_status()
            if status == "verified":
                raise OTPError("This OTP was already used. Generate a new one.", 409, "OTP_ALREADY_USED")
            if status == "revoked":
                raise OTPError("This OTP was revoked.", 410, "OTP_REVOKED")
            if status == "expired":
                raise OTPError("This OTP has expired. Generate a new one.", 410, "OTP_EXPIRED")
            if status == "locked":
                raise OTPError("Too many wrong attempts. This OTP is locked.", 429, "OTP_LOCKED")

            # constant-time comparison avoids timing attacks
            if hmac.compare_digest(_hash(otp, record.salt), record.otp_hash):
                record.status = "verified"
                self.stats["verified"] += 1
                return record

            record.attempts += 1
            self.stats["failed_attempts"] += 1
            remaining = record.max_attempts - record.attempts
            if remaining <= 0:
                record.status = "locked"
            raise OTPError(
                "Incorrect OTP." + (" No attempts left; the OTP is now locked." if remaining <= 0 else ""),
                401, "OTP_INCORRECT", {"attempts_remaining": max(remaining, 0)},
            )

    def revoke(self, otp_id):
        with self._lock:
            record = self._records.get(otp_id)
            if record is None:
                raise OTPError("No OTP exists with this otp_id.", 404, "OTP_NOT_FOUND", {"otp_id": otp_id})
            record.status = "revoked"
            return record

    def snapshot(self):
        now = time.time()
        with self._lock:
            active = sum(1 for r in self._records.values() if r.current_status(now) == "pending")
            return {**self.stats, "active": active}

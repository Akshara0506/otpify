import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as service  # noqa: E402
from otp_service import OTPStore  # noqa: E402


@pytest.fixture
def client():
    service.store = OTPStore()  # fresh in-memory store per test
    service.app.config["TESTING"] = True
    with service.app.test_client() as c:
        yield c


def gen(client, **overrides):
    body = {"identifier": "a@b.com", **overrides}
    return client.post("/api/otp/generate", json=body)


# ---- success paths --------------------------------------------------------
def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json["data"]["status"] == "UP"
    assert "X-Request-ID" in r.headers and "X-Response-Time" in r.headers


def test_index_lists_endpoints(client):
    r = client.get("/api")
    assert r.status_code == 200 and len(r.json["data"]["endpoints"]) >= 6


def test_ui_served(client):
    r = client.get("/")
    assert r.status_code == 200 and b"OTPify" in r.data


def test_generate_numeric(client):
    r = gen(client, length=8)
    assert r.status_code == 201
    d = r.json["data"]
    assert len(d["otp"]) == 8 and d["otp"].isdigit()
    assert r.headers["Location"] == f"/api/otp/{d['otp_id']}"
    assert r.headers["Cache-Control"] == "no-store"


def test_generate_alphanumeric(client):
    d = gen(client, type="alphanumeric", length=10).json["data"]
    assert len(d["otp"]) == 10 and not set(d["otp"]) & set("01OIL")


def test_quick_get(client):
    r = client.get("/api/otp/quick?length=4")
    assert r.status_code == 201 and len(r.json["data"]["otp"]) == 4


def test_verify_success_then_single_use(client):
    d = gen(client).json["data"]
    r = client.post("/api/otp/verify", json={"otp_id": d["otp_id"], "otp": d["otp"]})
    assert r.status_code == 200 and r.json["data"]["verified"] is True
    again = client.post("/api/otp/verify", json={"otp_id": d["otp_id"], "otp": d["otp"]})
    assert again.status_code == 409 and again.json["error"]["code"] == "OTP_ALREADY_USED"


def test_status_never_reveals_code(client):
    d = gen(client).json["data"]
    r = client.get(f"/api/otp/{d['otp_id']}")
    assert r.status_code == 200 and "otp" not in r.json["data"]
    assert r.json["data"]["status"] == "pending"


def test_revoke(client):
    d = gen(client).json["data"]
    assert client.delete(f"/api/otp/{d['otp_id']}").status_code == 200
    r = client.post("/api/otp/verify", json={"otp_id": d["otp_id"], "otp": d["otp"]})
    assert r.status_code == 410 and r.json["error"]["code"] == "OTP_REVOKED"


# ---- error paths ------------------------------------------------------------
@pytest.mark.parametrize("body,field", [
    ({}, "identifier"),
    ({"identifier": "x", "length": 99}, "length"),
    ({"identifier": "x", "ttl": 5}, "ttl"),
    ({"identifier": "x", "type": "emoji"}, "type"),
    ({"identifier": "x", "length": "six"}, "length"),
    ({"identifier": 123}, "identifier"),
])
def test_generate_validation(client, body, field):
    r = client.post("/api/otp/generate", json=body)
    assert r.status_code == 400
    assert r.json["error"]["code"] == "VALIDATION_FAILED"
    assert field in r.json["error"]["details"]


def test_malformed_json(client):
    r = client.post("/api/otp/generate", data='{"identifier":', content_type="application/json")
    assert r.status_code == 400 and r.json["error"]["code"] == "MALFORMED_JSON"


def test_wrong_content_type(client):
    r = client.post("/api/otp/generate", data="identifier=x", content_type="text/plain")
    assert r.status_code == 415


def test_verify_wrong_code_then_lock(client):
    d = gen(client, max_attempts=2).json["data"]
    r1 = client.post("/api/otp/verify", json={"otp_id": d["otp_id"], "otp": "XXXXXX"})
    assert r1.status_code == 401 and r1.json["error"]["details"]["attempts_remaining"] == 1
    r2 = client.post("/api/otp/verify", json={"otp_id": d["otp_id"], "otp": "XXXXXX"})
    assert r2.status_code == 401 and r2.json["error"]["details"]["attempts_remaining"] == 0
    r3 = client.post("/api/otp/verify", json={"otp_id": d["otp_id"], "otp": d["otp"]})
    assert r3.status_code == 429 and r3.json["error"]["code"] == "OTP_LOCKED"


def test_verify_missing_fields(client):
    r = client.post("/api/otp/verify", json={"otp_id": ""})
    assert r.status_code == 400 and {"otp_id", "otp"} <= set(r.json["error"]["details"])


def test_verify_unknown_id(client):
    r = client.post("/api/otp/verify", json={"otp_id": "nope", "otp": "123456"})
    assert r.status_code == 404 and r.json["error"]["code"] == "OTP_NOT_FOUND"


def test_expired(client, monkeypatch):
    d = gen(client, ttl=30).json["data"]
    real = time.time
    monkeypatch.setattr("otp_service.time.time", lambda: real() + 31)
    r = client.post("/api/otp/verify", json={"otp_id": d["otp_id"], "otp": d["otp"]})
    assert r.status_code == 410 and r.json["error"]["code"] == "OTP_EXPIRED"


def test_rate_limit(client):
    for _ in range(5):
        assert gen(client, identifier="spam@x.com").status_code == 201
    r = gen(client, identifier="spam@x.com")
    assert r.status_code == 429 and "Retry-After" in r.headers


def test_unknown_route_and_method(client):
    assert client.get("/api/nothing").json["error"]["code"] == "ROUTE_NOT_FOUND"
    r = client.put("/api/otp/verify", json={})
    assert r.status_code == 405 and r.json["error"]["code"] == "METHOD_NOT_ALLOWED"


def test_unexpected_error_is_json_500(client, monkeypatch):
    def boom():
        raise RuntimeError("boom")
    monkeypatch.setattr(service.store, "snapshot", boom)
    r = client.get("/api/stats")
    assert r.status_code == 500 and r.json["error"]["code"] == "INTERNAL_ERROR"

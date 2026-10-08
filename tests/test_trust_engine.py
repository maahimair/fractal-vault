# tests/test_trust_engine.py
# Unit and integration coverage for the Flask trust engine.
#
# Covers the controls the gateway relies on: input validation, the rule-based
# score, the API-key guards, and the HTTP status codes the gateway branches on.

import pytest

from conftest import INTERNAL_KEY, LOG_KEY


# ─── Validation ───────────────────────────────────────────────────────────────

def test_validate_input_rejects_unknown_fields():
    from app import validate_input

    sanitized, errors = validate_input({"failed_logins": 1, "is_admin": True})
    assert sanitized is None
    assert any("is_admin" in e for e in errors)


def test_validate_input_rejects_out_of_range_failed_logins():
    from app import validate_input

    _, errors = validate_input({"failed_logins": 21})
    assert errors, "failed_logins above the cap of 20 must be rejected"


def test_validate_input_rejects_boolean_for_failed_logins():
    from app import validate_input

    # bool is a subclass of int in Python; the check must exclude it explicitly.
    _, errors = validate_input({"failed_logins": True})
    assert errors


def test_validate_input_rejects_non_boolean_flags():
    from app import validate_input

    _, errors = validate_input({"unusual_location": "yes"})
    assert errors


def test_validate_input_accepts_clean_payload():
    from app import validate_input

    sanitized, errors = validate_input(
        {"failed_logins": 2, "unusual_location": True, "unknown_device": False}
    )
    assert errors == []
    assert sanitized["failed_logins"] == 2
    assert sanitized["unusual_location"] is True
    # Absent fields default rather than error out.
    assert sanitized["high_request_rate"] is False


# ─── Rule-based scoring ───────────────────────────────────────────────────────

def test_trust_score_drops_with_risk_factors():
    from app import calculate_trust_score

    clean = calculate_trust_score({"failed_logins": 0})
    messy = calculate_trust_score(
        {"failed_logins": 5, "unusual_location": True,
         "unknown_device": True, "high_request_rate": True}
    )
    assert clean == 100
    assert messy == 0  # 100 - 50 - 20 - 25 - 15 clamps at 0


def test_trust_score_stays_within_bounds():
    from app import calculate_trust_score

    for failed in range(0, 21):
        score = calculate_trust_score({"failed_logins": failed})
        assert 0 <= score <= 100


# ─── Endpoint guards ──────────────────────────────────────────────────────────

def test_evaluate_trust_requires_internal_key(client):
    res = client.post("/evaluate-trust", json={"failed_logins": 0})
    assert res.status_code == 403


def test_evaluate_trust_rejects_wrong_internal_key(client):
    res = client.post(
        "/evaluate-trust",
        json={"failed_logins": 0},
        headers={"X-Internal-Key": "not-the-right-key"},
    )
    assert res.status_code == 403


def test_logs_endpoint_requires_log_api_key(client):
    assert client.get("/logs").status_code == 401
    assert client.get("/logs", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/logs", headers={"X-API-Key": LOG_KEY}).status_code == 200


def test_health_is_public(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"


# ─── Evaluate-trust behaviour ─────────────────────────────────────────────────

def test_evaluate_trust_allows_clean_request(client, auth_headers):
    res = client.post("/evaluate-trust", json={"failed_logins": 0}, headers=auth_headers)
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "ALLOWED"
    assert body["trust_score"] >= 70


def test_evaluate_trust_denies_high_risk_request(client, auth_headers):
    res = client.post(
        "/evaluate-trust",
        json={
            "failed_logins": 12,
            "unusual_location": True,
            "unknown_device": True,
            "high_request_rate": True,
        },
        headers=auth_headers,
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "DENIED"
    assert body["trust_score"] < 40


def test_evaluate_trust_requires_json_content_type(client, auth_headers):
    res = client.post(
        "/evaluate-trust", data="failed_logins=1", headers=auth_headers
    )
    assert res.status_code == 415


def test_evaluate_trust_rejects_malformed_json(client, auth_headers):
    res = client.post(
        "/evaluate-trust",
        data="{not json",
        headers={**auth_headers, "Content-Type": "application/json"},
    )
    assert res.status_code == 400


def test_evaluate_trust_rejects_validation_failure(client, auth_headers):
    res = client.post(
        "/evaluate-trust",
        json={"failed_logins": 99},
        headers=auth_headers,
    )
    assert res.status_code == 422


def test_evaluate_trust_never_leaks_anomaly_score(client, auth_headers):
    # The raw anomaly score is deliberately withheld so callers cannot probe
    # the decision boundary by watching the score drift.
    res = client.post(
        "/evaluate-trust",
        json={"failed_logins": 3, "unknown_device": True},
        headers=auth_headers,
    )
    body = res.get_json()
    assert "anomaly_score" not in body
    assert "is_anomaly" in body


# ─── HTTP status preservation ─────────────────────────────────────────────────

def test_unknown_route_returns_404_not_500(client):
    # A catch-all Exception handler must not swallow HTTPExceptions and turn
    # them into 500s; the gateway branches on these status codes.
    assert client.get("/definitely-not-a-route").status_code == 404


def test_wrong_method_returns_405(client, auth_headers):
    res = client.get("/evaluate-trust", headers=auth_headers)
    assert res.status_code == 405


def test_oversized_body_is_rejected(client, auth_headers):
    huge = {"failed_logins": 0, "unusual_location": False,
            "unknown_device": False, "high_request_rate": False,
            "padding": "A" * (17 * 1024)}
    res = client.post("/evaluate-trust", json=huge, headers=auth_headers)
    assert res.status_code == 413
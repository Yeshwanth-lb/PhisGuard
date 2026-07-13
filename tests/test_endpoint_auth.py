"""Auth-enforcement tests: previously-unauthenticated core endpoints now require auth.

Uses TestClient WITHOUT entering the lifespan (no `with`), so SMTP/ML/scheduler startup
is not triggered — we only exercise the routing + auth dependencies.
"""
from fastapi.testclient import TestClient

import app.main as main

client = TestClient(main.app)

# (method, path, json_body_or_None)
READ_ENDPOINTS = [
    ("get", "/api/scans", None),
    ("get", "/api/stats", None),
    ("get", "/api/quarantine", None),
    ("get", "/api/scan/abc", None),
    ("get", "/api/denylist", None),
    ("get", "/api/settings", None),
    ("get", "/api/soar/status", None),
    ("get", "/api/scan/abc/screenshot", None),
]
MUTATE_ENDPOINTS = [
    ("post", "/api/scan/abc/release", {}),
    ("delete", "/api/scan/abc", None),
    ("post", "/api/denylist", {"kind": "domain", "value": "x.com"}),
    ("delete", "/api/denylist/domain/x.com", None),
]


def _call(method, path, body):
    fn = getattr(client, method)
    return fn(path, json=body) if body is not None else fn(path)


def test_read_endpoints_require_auth():
    for method, path, body in READ_ENDPOINTS:
        r = _call(method, path, body)
        assert r.status_code in (401, 403), f"{method} {path} -> {r.status_code} (expected 401/403)"


def test_mutating_endpoints_require_auth():
    for method, path, body in MUTATE_ENDPOINTS:
        r = _call(method, path, body)
        assert r.status_code in (401, 403), f"{method} {path} -> {r.status_code} (expected 401/403)"


def test_health_stays_public():
    # /health must remain reachable without auth (used by Docker healthcheck).
    assert client.get("/health").status_code == 200

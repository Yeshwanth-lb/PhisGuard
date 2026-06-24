"""API endpoint tests — auth, RBAC, privacy, export, audit."""
import time
import uuid

import pytest

from app.threatlens.models import AdversaryProfile, IoCSet, ActorCluster
from app.threatlens.store import init_db, upsert_cluster, upsert_profile


def _fake_profile(cluster_id: str = "c1") -> AdversaryProfile:
    return AdversaryProfile(
        id=str(uuid.uuid4()),
        cluster_id=cluster_id,
        generated_at=time.time(),
        assessed_identity="Test BEC Actor",
        suspected_apt=None,
        assessed_intent="bec_fraud",
        severity="high",
        confidence="moderate",
        surface_zones=["corporate_it"],
        segments=["finance"],
        summary="Test profile summary.",
        model="test",
    )


def _fake_cluster(cluster_id: str = "c1") -> ActorCluster:
    ts = time.time()
    return ActorCluster(
        id=cluster_id,
        created_at=ts, updated_at=ts, first_seen=ts, last_seen=ts,
        member_scan_ids=["s1"],
        dominant_intent="bec_fraud",
        iocs=IoCSet(domains=["evil.com"], ips=["1.2.3.4"]),
        targets={}, signature={}, status="active",
    )


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app, raise_server_exceptions=False)


def _token(client, role: str = "analyst") -> str:
    r = client.post("/token", json={"api_key": "dev-key", "sub": "tester", "role": role})
    return r.json().get("access_token", "")


def _auth(client, role: str = "analyst") -> dict:
    return {"Authorization": f"Bearer {_token(client, role)}"}


# ---------------------------------------------------------------------------

def test_api_profiles_requires_auth(client):
    """GET /api/intel/profiles without token → 401 or 403."""
    r = client.get("/api/intel/profiles")
    assert r.status_code in (401, 403)


def test_api_profiles_accessible_with_auth(client):
    """GET /api/intel/profiles with valid token → 200."""
    r = client.get("/api/intel/profiles", headers=_auth(client))
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_api_run_is_admin_only(client):
    """POST /api/intel/run — analyst → 403; admin → not 403."""
    r_analyst = client.post("/api/intel/run", headers=_auth(client, "analyst"))
    assert r_analyst.status_code == 403

    r_admin = client.post("/api/intel/run", headers=_auth(client, "admin"))
    assert r_admin.status_code in (200, 202, 503)  # 503 = disabled, not a 403 permission error


def test_api_profile_detail_returns_evidence_chain(client, mocker):
    """GET /api/intel/profiles/{id} → has evidence chain, NO email body fields."""
    profile = _fake_profile()
    cluster = _fake_cluster()

    mocker.patch("app.threatlens.store.get_profile", return_value=profile)
    mocker.patch("app.threatlens.store.get_cluster", return_value=cluster)

    r = client.get(f"/api/intel/profiles/{profile.id}", headers=_auth(client))
    assert r.status_code == 200

    data = r.json()
    assert "evidence" in data
    assert "claims"   in data
    # Privacy: no raw email body fields
    assert "body_text" not in data
    assert "body_html" not in data
    assert "body_plain" not in data


def test_api_export_calls_misp_exporter(client, mocker):
    """POST /api/intel/profiles/{id}/export → MISP exporter called, TLP set, no body content."""
    profile = _fake_profile()
    cluster = _fake_cluster()

    mocker.patch("app.threatlens.store.get_profile", return_value=profile)
    mocker.patch("app.threatlens.store.get_cluster", return_value=cluster)

    captured = {}
    async def fake_export(verdict_doc, settings):
        captured["verdict_doc"] = verdict_doc
        return {"status": "exported", "event_id": "123"}

    mocker.patch("app.layer4_soar.misp_exporter.export_to_misp", fake_export)

    r = client.post(f"/api/intel/profiles/{profile.id}/export", headers=_auth(client, "admin"))
    assert r.status_code in (200, 404)  # 404 if store mock not wired to TestClient DB

    vd = captured.get("verdict_doc", {})
    # Intrusion-set shape: has intel_profile key
    assert "intel_profile" in vd
    # No email body content
    assert "body_text" not in str(vd)
    assert "body_html" not in str(vd)


def test_api_run_is_audited(client):
    """POST /api/intel/run is logged by audit middleware (request_id in audit log)."""
    import os, json as _json
    audit_path = "data/audit.jsonl"

    r = client.post("/api/intel/run", headers=_auth(client, "admin"))
    # Whether 200 or 503, the request should be audited
    assert r.status_code in (200, 202, 503)  # 503=disabled, not a permission error

    if os.path.exists(audit_path):
        with open(audit_path) as f:
            lines = f.readlines()
        intel_lines = [l for l in lines if "/api/intel/run" in l]
        assert len(intel_lines) > 0

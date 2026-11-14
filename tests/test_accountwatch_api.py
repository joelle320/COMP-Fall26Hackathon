"""AccountWatch authorization and metadata-only ingestion through real HTTP routes."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import shutil
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session

from sentinel.api import create_app
from sentinel.core import Engine
from sentinel.store import Record


ADMIN = "enterprise-security-test-administrator"
ANALYST = "enterprise-security-test-analyst"


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def seed_template(tmp_path_factory):
    directory = tmp_path_factory.mktemp("accountwatch-api-template")
    engine = Engine(directory)
    engine.accountwatch.seed()
    engine.store.db.dispose()
    return directory


@pytest.fixture
def api(tmp_path, seed_template):
    directory = tmp_path / "state"
    shutil.copytree(seed_template, directory)
    app = create_app(directory, admin_token=ADMIN, analyst_token=ANALYST, testing=True)
    with TestClient(app) as client:
        yield client, app.state.engine


def identity(engine, index=0):
    return [row for row in engine.accountwatch.identities() if row["kind"] == "employee"][index]


def event(identity_id, session_id=None, **updates):
    body = {
        "identity_id": identity_id,
        "authentication_session_id": session_id or "test-auth-" + uuid4().hex[:12],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "category": "auth_success", "application": "support-console", "resource_category": "internal",
        "device_id": "test-device", "region": "US-East", "mfa_verified": True,
    }
    return {**body, **updates}


@pytest.mark.parametrize("path", [
    "/api/accountwatch/overview", "/api/accountwatch/identities", "/api/accountwatch/anomalies",
    "/api/accountwatch/responses", "/api/incidents/correlated", "/api/command", "/api/integrations",
])
def test_analytics_require_security_role_and_reject_agent_credentials(api, path):
    client, engine = api
    agent = engine.create_session("analytics-unprivileged-agent")
    assert client.get(path).status_code in {401, 403}
    assert client.get(path, headers=bearer(agent["token"])).status_code == 403
    assert client.get(path, headers=bearer(ANALYST)).status_code == 200
    assert client.get(path, headers=bearer(ADMIN)).status_code == 200


def test_roles_are_server_derived_and_analyst_cannot_administer_agentguard(api):
    client, _ = api
    assert client.get("/api/auth/role", headers=bearer(ADMIN)).json()["role"] == "admin"
    assert client.get("/api/auth/role", headers=bearer(ANALYST)).json()["role"] == "analyst"
    for method, path, body in [
        ("get", "/api/state", None),
        ("post", "/api/sessions", {"agent_id": "analyst-granted-agent", "capabilities": ["*"]}),
        ("post", "/api/accountwatch/seed", {}),
        ("post", "/api/accountwatch/retention/purge", {}),
        ("post", "/api/accountwatch/responses/nonexistent/approve", {"approved": True, "note": "Approve myself"}),
        ("post", "/api/accountwatch/sessions/nonexistent/verify", {"note": "Approve myself"}),
        ("post", "/api/enterprise/demo/all", {}),
    ]:
        kwargs = {"json": body} if body is not None else {}
        result = getattr(client, method)(path, headers=bearer(ANALYST), **kwargs)
        assert result.status_code == 403, (path, result.text)


@pytest.mark.parametrize("field", ["password", "access_token", "private_message", "keystrokes", "screenshot", "ground_truth", "risk_score", "tenant_id"])
def test_ingestion_does_not_accept_content_credentials_labels_or_risk_assertions(api, field):
    client, engine = api
    secret = "sk_test_METADATA_REJECTION_SYNTHETIC_12345678"
    payload = event(identity(engine)["id"], **{field: secret})
    response = client.post("/api/accountwatch/events", headers=bearer(ANALYST), json=payload)
    assert response.status_code == 422, response.text
    assert secret not in response.text


@pytest.mark.parametrize("updates", [
    {"file_count": -1}, {"sensitive_file_count": -10}, {"data_mb": -1.5},
    {"failed_attempts": -1}, {"duration_minutes": -30},
    {"timestamp": "not-a-time"}, {"timestamp": "2099-01-01T12:00:00Z"},
])
def test_invalid_event_metadata_fails_before_ingestion(api, updates):
    client, engine = api
    before = len(engine.store.list("aw_event"))
    response = client.post("/api/accountwatch/events", headers=bearer(ANALYST), json=event(identity(engine)["id"], **updates))
    assert response.status_code in {400, 422}, response.text
    assert len(engine.store.list("aw_event")) == before


def test_authentication_session_cannot_be_reassigned_to_another_identity(api):
    client, engine = api
    first, second = identity(engine, 0), identity(engine, 1)
    session_id = "test-auth-owner-binding"
    first_event = client.post("/api/accountwatch/events", headers=bearer(ANALYST), json=event(first["id"], session_id))
    assert first_event.status_code in {200, 201}, first_event.text
    reassignment = client.post("/api/accountwatch/events", headers=bearer(ANALYST), json=event(second["id"], session_id))
    assert reassignment.status_code in {400, 403, 409}, reassignment.text
    binding = engine.store.get("aw_auth_session", session_id)
    assert binding["identity_id"] == first["id"]


def test_unknown_identity_cannot_create_synthetic_authentication_session(api):
    client, engine = api
    before = len(engine.store.list("aw_auth_session"))
    response = client.post("/api/accountwatch/events", headers=bearer(ANALYST), json=event("unregistered-identity"))
    assert response.status_code in {400, 404}, response.text
    assert len(engine.store.list("aw_auth_session")) == before


def test_analyst_can_inspect_baseline_but_cannot_send_arbitrary_updates(api):
    client, engine = api
    identifier = identity(engine)["id"]
    path = f"/api/accountwatch/identities/{identifier}/baseline"
    before = client.get(path, headers=bearer(ANALYST))
    assert before.status_code == 200
    rewrite = client.post(path, headers=bearer(ANALYST), json={"file_count": {"median": 999999}, "risk_score": 0})
    assert rewrite.status_code in {404, 405}
    assert client.get(path, headers=bearer(ANALYST)).json() == before.json()


def test_connector_previews_never_claim_live_cisco_integrations(api):
    client, _ = api
    response = client.get("/api/integrations", headers=bearer(ANALYST))
    assert response.status_code == 200
    payload = response.json()
    connectors = payload if isinstance(payload, list) else payload["connectors"]
    assert {item["id"] for item in connectors} >= {"duo", "xdr", "secure_access", "identity_intelligence", "splunk"}
    assert all(item["status"] == "mock" and item["official_integration"] is False for item in connectors)
    encoded = json.dumps(connectors)
    assert ADMIN not in encoded and ANALYST not in encoded


def demo_anomaly(engine):
    result = engine.accountwatch.demo("c")
    assert result["passed"]
    return result["steps"][-1]["result"]["anomaly"]


def test_analyst_can_correct_expected_behavior_close_and_reopen_with_audit_history(api):
    client, engine = api
    anomaly = demo_anomaly(engine)
    path = f"/api/accountwatch/anomalies/{anomaly['id']}/review"
    for action, expected in [("expected", "expected"), ("close", "closed"), ("reopen", "open")]:
        response = client.post(path, headers=bearer(ANALYST), json={"action": action, "note": "Verified synthetic business exception"})
        assert response.status_code == 200, response.text
        assert response.json()["status"] == expected
    history = engine.store.get("aw_anomaly", anomaly["id"])["review_history"]
    assert [item["action"] for item in history][-3:] == ["expected", "close", "reopen"]
    assert all(item["reviewer"] == "local-analyst" for item in history)
    assert engine.accountwatch.detail(anomaly["identity_id"])["identity"]["status"] == "active"
    assert engine.verify_audit()["valid"]


def test_analyst_containment_proposal_cannot_apply_itself_or_disable_entire_account(api):
    client, engine = api
    anomaly = demo_anomaly(engine)
    proposal = client.post(f"/api/accountwatch/anomalies/{anomaly['id']}/review", headers=bearer(ANALYST),
                           json={"action": "propose_containment", "note": "Restrict only the named authentication session"})
    assert proposal.status_code == 200, proposal.text
    response = engine.accountwatch.responses()[0]
    assert response["status"] == "pending"
    route = f"/api/accountwatch/responses/{response['id']}/approve"
    denied = client.post(route, headers=bearer(ANALYST), json={"approved": True, "note": "I approve my own proposal"})
    assert denied.status_code == 403, denied.text
    assert engine.store.get("aw_response", response["id"])["status"] == "pending"
    approved = client.post(route, headers=bearer(ADMIN), json={"approved": True, "note": "Authorize this scoped simulation"})
    assert approved.status_code == 200, approved.text
    assert engine.store.get("aw_auth_session", response["authentication_session_id"])["status"] == "restricted"
    assert engine.accountwatch.detail(anomaly["identity_id"])["identity"]["status"] == "active"
    replay = client.post(route, headers=bearer(ADMIN), json={"approved": True, "note": "Attempt repeated approval"})
    assert replay.status_code in {400, 403, 409}, replay.text


def test_agent_cannot_modify_anomaly_review_even_if_it_knows_incident_identifier(api):
    client, engine = api
    anomaly = demo_anomaly(engine)
    agent = engine.create_session("review-attacker")
    response = client.post(f"/api/accountwatch/anomalies/{anomaly['id']}/review", headers=bearer(agent["token"]),
                           json={"action": "expected", "note": "I assert this should be ignored"})
    assert response.status_code == 403
    assert engine.store.get("aw_anomaly", anomaly["id"])["status"] == "open"


def test_review_payload_cannot_smuggle_an_approval_or_identity_assertion(api):
    client, engine = api
    anomaly = demo_anomaly(engine)
    response = client.post(f"/api/accountwatch/anomalies/{anomaly['id']}/review", headers=bearer(ANALYST), json={
        "action": "propose_containment", "note": "Review synthetic event", "approved": True, "reviewer": "local-authority",
    })
    assert response.status_code == 422, response.text
    assert engine.accountwatch.responses() == []


def test_unknown_review_identifiers_fail_without_creating_investigation_state(api):
    client, engine = api
    before = len(engine.store.list("aw_review"))
    for path in ("/api/accountwatch/anomalies/unknown-anomaly/review", "/api/incidents/correlated/unknown-correlation/review"):
        response = client.post(path, headers=bearer(ANALYST), json={"action": "close", "note": "Unknown synthetic incident"})
        assert response.status_code in {400, 404}, response.text
    assert len(engine.store.list("aw_review")) == before


def test_accountwatch_and_command_refuse_tampered_identity_records(api):
    client, engine = api
    owner = identity(engine)["id"]
    with Session(engine.store.db) as database:
        row = database.get(Record, "aw_identity:" + owner)
        original = json.loads(row.body)
        row.body = json.dumps({**original, "role": "unaudited-administrator"})
        database.commit()
    assert engine.verify_audit()["valid"] is False
    for path in ("/api/accountwatch/overview", "/api/accountwatch/identities", "/api/command", "/api/incidents/correlated"):
        response = client.get(path, headers=bearer(ANALYST))
        assert response.status_code == 503, (path, response.text)


def test_seed_analytics_responses_never_return_admin_analyst_or_agent_secrets(api):
    client, engine = api
    agent = engine.create_session("private-agent-credential")
    for path in ("/api/accountwatch/overview", "/api/command", "/api/incidents/correlated"):
        response = client.get(path, headers=bearer(ANALYST))
        assert response.status_code == 200, response.text
        assert ADMIN not in response.text and ANALYST not in response.text
        assert agent["token"] not in response.text
        assert "token_hash" not in response.text

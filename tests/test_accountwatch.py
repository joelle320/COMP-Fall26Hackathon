from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from pydantic import ValidationError
from sentinel.accountwatch import AccountWatch
from sentinel.accountwatch_models import ActivityEvent
from sentinel.enterprise_evaluation import evaluate_accountwatch
from sentinel.store import Store
from sentinel.synthetic import generate_dataset


@pytest.fixture
def service(tmp_path):
    result = AccountWatch(Store(tmp_path))
    result.seed()
    return result


def event(service, category="auth_success", **kwargs):
    baseline = service.baseline("emp-001")
    return {"identity_id": "emp-001", "authentication_session_id": "unit-auth", "timestamp": datetime.now(timezone.utc).isoformat(),
            "category": category, "application": baseline["applications"][0], "device_id": baseline["familiar_devices"][0], "region": baseline["regions"][0],
            "approved_after_hours": True, "mfa_verified": True, **kwargs}


def test_dataset_has_separate_normal_training_and_heldout_labels():
    dataset = generate_dataset(reference_time=datetime(2026, 11, 14, 12, tzinfo=timezone.utc))
    assert len(dataset["identities"]) == 23
    assert len(dataset["training"]) == 690
    assert len(dataset["evaluation"]) == 16
    assert max(datetime.fromisoformat(e["timestamp"]) for e in dataset["training"]) < min(datetime.fromisoformat(e["timestamp"]) for c in dataset["evaluation"] for e in c["events"])
    assert all("label" not in e for case in dataset["evaluation"] for e in case["events"])


def test_seed_idempotent_baseline_not_changed_by_ingest(service):
    before = service.baseline("emp-001")
    assert service.seed()["seeded"] is False
    service.ingest(event(service))
    service.ingest(event(service, "file_access", file_count=650, sensitive_file_count=500, resource_category="confidential"))
    assert service.baseline("emp-001") == before


def test_benign_after_hours_and_travel_do_not_require_review(service):
    result = service.demo("a")
    assert result["passed"]
    assert result["steps"][0]["result"]["anomaly"] is None
    result = service.ingest(event(service, region="EU-West", approved_travel=True))
    assert result["risk"]["score"] < service.policy["review_score"]


@pytest.mark.parametrize("scenario", ["b", "c", "d"])
def test_contextual_scenarios_raise_explained_review_priority(service, scenario):
    result = service.demo(scenario)
    assert result["passed"]
    assert result["steps"][-1]["result"]["anomaly"]["classification"] == "behavioral_anomaly"
    assert all(identity["status"] == "active" for identity in service.identities())


def test_caller_familiarity_does_not_override_baseline(service):
    result = service.ingest(event(service, device_id="never-seen", device_familiar=True))
    assert result["event"]["device_familiar"] is False
    assert "UNFAMILIAR_DEVICE" in result["anomaly"]["reason_codes"]


def test_extra_content_fields_rejected_before_persistence(service):
    count = len(service.store.list("aw_event"))
    with pytest.raises(ValidationError):
        service.ingest({**event(service), "private_message": "unrelated content"})
    assert len(service.store.list("aw_event")) == count
    with pytest.raises(ValueError):
        service.ingest(event(service, device_id="sk_test_SYNTHETIC_UNACCEPTABLE_123456"))
    assert "sk_test_SYNTHETIC_UNACCEPTABLE_123456" not in str(service.store.list("aw_auth_session"))


def test_binding_cannot_switch_identity_or_use_failed_authentication(service):
    service.ingest(event(service, "auth_failure", failed_attempts=2))
    with pytest.raises(PermissionError):
        service.validate_binding("emp-001", "unit-auth")
    with pytest.raises(PermissionError):
        service.ingest(event(service, "file_access", file_count=3))
    service.ingest(event(service))
    with pytest.raises(PermissionError):
        service.ingest(event(service, identity_id="emp-002"))
    assert service.validate_binding("emp-001", "unit-auth")["identity_id"] == "emp-001"


def test_review_and_scoped_containment_require_separate_authority_call(service):
    service.ingest(event(service))
    result = service.ingest(event(service, "file_access", file_count=650, sensitive_file_count=500, resource_category="confidential"))
    review = service.review(result["anomaly"]["id"], "propose_containment", "Review this exact synthetic session.", "analyst")
    assert service.store.get("aw_auth_session", "unit-auth")["status"] == "active"
    service.approve_response(review["response_id"], True, "administrator")
    assert service.store.get("aw_auth_session", "unit-auth")["status"] == "restricted"
    assert all(item["status"] == "active" for item in service.identities())
    service.verify_session("emp-001", "unit-auth", "administrator", "Mock identity ownership verification completed.")
    assert service.validate_binding("emp-001", "unit-auth")["status"] == "active"


def test_gateway_score_cannot_revoke_unrelated_reads_or_grant_capabilities(service):
    service.ingest(event(service, device_id="new-device"))
    service.ingest(event(service, "privilege_change", device_id="new-device", privilege="admin"))
    session = {"owner_identity_id": "emp-001", "authentication_session_id": "unit-auth", "capabilities": ["files:read"]}
    assert service.gateway_findings(session, {"tool": "files", "operation": "read", "resource": "readme.txt"}) == []
    findings = service.gateway_findings(session, {"tool": "files", "operation": "write", "resource": "config/agent.json"})
    assert findings[0]["risk_level"] == 2
    assert session["capabilities"] == ["files:read"]
    service.verify_session("emp-001", "unit-auth", "administrator", "Explicit mock step-up authorized.")
    assert service.gateway_findings(session, {"tool": "files", "operation": "write", "resource": "config/agent.json"}) == []


def test_retention_erases_raw_event_and_baseline_history_without_breaking_audit(service):
    result = service.ingest(event(service))
    report = service.purge_expired(datetime.now(timezone.utc) + timedelta(days=100))
    assert report["purged_events"] == 1
    assert report["purged_baselines"] == 23
    assert service.store.get("aw_event", result["event"]["id"])["purged"]
    with pytest.raises(ValueError):
        service.baseline("emp-001")
    assert service.store.verify()["valid"]
    assert service.seed()["seeded"]
    assert service.baseline("emp-001")["sample_count"] == 30


def test_risk_policy_thresholds_must_cover_normalized_range(tmp_path):
    with pytest.raises(ValueError):
        AccountWatch(Store(tmp_path), {"thresholds": [{"label": "high", "min": 0, "max": 100}]})


def test_auth_frequency_uses_personal_history_and_conservative_window(service):
    baseline = service.baseline("emp-001")
    assert baseline["login_frequency"]["observed_daily_count"]["median"] > 0
    for index in range(baseline["login_frequency"]["upper_per_30_minutes"] + 1):
        result = service.ingest(event(service, authentication_session_id=f"frequency-{index}"))
    assert any(reason["code"] == "AUTHENTICATION_FREQUENCY" for reason in result["risk"]["reasons"])
    assert result["risk"]["score"] < service.policy["review_score"]


def test_collector_role_claim_cannot_override_trusted_role_configuration(service):
    service.ingest(event(service))
    result = service.ingest(event(service, "privilege_change", privilege="admin", authorized_role=True))
    assert result["event"]["authorized_role"] is False
    assert "PRIVILEGE_POLICY_VIOLATION" in result["anomaly"]["reason_codes"]
    assert result["risk"]["score"] >= 90


def test_heldout_fixture_evaluation_reports_measured_counts():
    result = evaluate_accountwatch()
    assert result["all_required_checks_passed"], result["cases"]
    assert result["dataset"]["normal_cases"] == 8
    assert result["dataset"]["anomalous_cases"] == 8
    assert result["metrics"]["baseline_unchanged_after_evaluation"]
    assert result["metrics"]["precision"]["denominator"] > 0

"""Synthetic enterprise metadata with separate normal training and held-out cases.

No real employees, private content, passwords, or authentication credentials are
represented. Ground-truth labels live on evaluation *cases*, never event payloads.
The generator never fits a baseline from the evaluation cases.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import random
from typing import Any
from zoneinfo import ZoneInfo


TENANT = "sentinel-demo"
LOCAL_ZONE = ZoneInfo("America/New_York")
ROLE_SETTINGS = {
    "support": {"application": "Support Portal", "files": 40, "resources": ["public", "internal"]},
    "engineering": {"application": "Source Control", "files": 70, "resources": ["public", "internal", "confidential"]},
    "security": {"application": "Security Console", "files": 65, "resources": ["public", "internal", "confidential"]},
    "finance": {"application": "Finance Sandbox", "files": 35, "resources": ["public", "internal", "confidential"]},
    "operations": {"application": "Infrastructure Console", "files": 55, "resources": ["public", "internal", "confidential"]},
}


def generate_dataset(seed: int = 42, reference_time: datetime | None = None) -> dict[str, Any]:
    """Return 23 identities, 690 normal rows, and 16 independently labelled cases.

    ``reference_time`` enables exact reproduction. Training ends two days before
    the held-out date; all generated timestamps precede the reference instant.
    Employee comparisons use local account time; stored timestamps include UTC
    offsets. Different employee volumes are normal, not labels of maliciousness.
    """
    rng = random.Random(seed)
    reference = reference_time or datetime.now(timezone.utc)
    if reference.tzinfo is None or reference.utcoffset() is None:
        raise ValueError("Synthetic reference_time must include a timezone")
    reference = reference.astimezone(LOCAL_ZONE)
    heldout = (reference - timedelta(days=1)).replace(hour=10, minute=0, second=0, microsecond=0)
    identities: list[dict] = []
    training: list[dict] = []
    roles = list(ROLE_SETTINGS)
    for index in range(1, 24):
        employee = index <= 20
        identity_id = f"emp-{index:03}" if employee else f"svc-{index - 20:03}"
        role = roles[(index - 1) % len(roles)] if employee else "operations"
        configuration = ROLE_SETTINGS[role]
        identity = {
            "id": identity_id,
            "name": f"Employee {index:03}" if employee else f"Service {index - 20:03}",
            "kind": "employee" if employee else "service",
            "role": role,
            "tenant_id": TENANT,
            "status": "active",
            "timezone": "America/New_York",
            "authorized_resource_categories": list(configuration["resources"]),
            "created_at": (heldout - timedelta(days=35)).isoformat(),
        }
        identities.append(identity)
        personal_volume = int(configuration["files"]) + ((index * 7) % 25) - 12
        for offset in range(30):
            day = heldout - timedelta(days=31 - offset)
            hour = rng.choice([8, 9, 9, 10, 11, 13, 14, 15, 16, 17]) if employee else (offset * 5 + index) % 24
            stamp = day.replace(hour=hour, minute=rng.choice([0, 10, 20, 30, 40]))
            volume = max(1, personal_volume + rng.randint(-7, 7))
            sensitive = int(volume * 0.12) if "confidential" in configuration["resources"] else 0
            training.append({
                "identity_id": identity_id,
                "authentication_session_id": f"train-{identity_id}-{offset:02}",
                "timestamp": stamp.isoformat(),
                "category": "auth_success" if offset % 3 == 0 else "file_access",
                "application": configuration["application"],
                "resource_category": "internal",
                "device_id": f"dev-{identity_id}",
                "region": "US-East",
                "file_count": volume,
                "sensitive_file_count": sensitive,
                "data_mb": round(volume * rng.uniform(0.1, 0.3), 2),
                "failed_attempts": 1 if offset % 11 == 0 else 0,
                "duration_minutes": rng.randint(25, 80),
                "authorized_role": True,
                "approved_after_hours": False,
                "approved_travel": False,
                "mfa_verified": True,
            })

    def event(identity_id: str, session: str, minute: int = 0, **changes: Any) -> dict:
        identity = next(item for item in identities if item["id"] == identity_id)
        configuration = ROLE_SETTINGS[identity["role"]]
        payload = {
            "identity_id": identity_id,
            "authentication_session_id": session,
            "timestamp": (heldout + timedelta(minutes=minute)).isoformat(),
            "category": "auth_success",
            "application": configuration["application"],
            "resource_category": "internal",
            "device_id": f"dev-{identity_id}",
            "region": "US-East",
            "file_count": 0,
            "sensitive_file_count": 0,
            "data_mb": 0.0,
            "failed_attempts": 0,
            "duration_minutes": 45,
            "authorized_role": True,
            "approved_after_hours": False,
            "approved_travel": False,
            "mfa_verified": True,
        }
        payload.update(changes)
        return payload

    def case(name: str, label: str, scenario: str, events: list[dict]) -> dict:
        return {"id": name, "label": label, "scenario": scenario, "events": events, "split": "evaluation"}

    evaluation = [
        case("normal-login", "normal", "routine_login", [event("emp-001", "eval-normal-login")]),
        case("normal-files", "normal", "routine_files", [
            event("emp-002", "eval-normal-files"),
            event("emp-002", "eval-normal-files", 2, category="file_access", file_count=70, sensitive_file_count=7, data_mb=12.0),
        ]),
        case("approved-after-hours", "normal", "benign_after_hours", [
            event("emp-003", "eval-after-hours", timestamp=heldout.replace(hour=2).isoformat(), approved_after_hours=True),
        ]),
        case("approved-travel", "normal", "benign_travel", [
            event("emp-004", "eval-travel", region="EU-West", approved_travel=True),
        ]),
        case("service-schedule", "normal", "normal_service_account", [
            event("svc-001", "eval-service", timestamp=heldout.replace(hour=3).isoformat(), application="Infrastructure Console"),
        ]),
        case("normal-sensitive-role", "normal", "authorized_sensitive_access", [
            event("emp-005", "eval-sensitive-role"),
            event("emp-005", "eval-sensitive-role", 3, category="file_access", resource_category="confidential", file_count=44, sensitive_file_count=4, data_mb=8.0),
        ]),
        case("normal-long-session", "normal", "normal_session_duration", [
            event("emp-006", "eval-duration"),
            event("emp-006", "eval-duration", 30, category="session_end", duration_minutes=65),
        ]),
        case("normal-low-failure", "normal", "single_failed_attempt", [
            event("emp-007", "eval-one-failure", category="auth_failure", failed_attempts=1),
            event("emp-007", "eval-one-failure", 1),
        ]),
        case("new-device-privilege", "anomalous", "new_device_privilege_sequence", [
            event("emp-008", "eval-device-privilege", device_id="unknown-device-008", mfa_verified=False),
            event("emp-008", "eval-device-privilege", 2, category="privilege_change", privilege="admin", device_id="unknown-device-008", mfa_verified=False, authorized_role=False),
        ]),
        case("failed-success-sensitive", "anomalous", "possible_account_takeover", [
            event("emp-009", "eval-takeover", category="auth_failure", failed_attempts=3),
            event("emp-009", "eval-takeover", 1, category="auth_failure", failed_attempts=3),
            event("emp-009", "eval-takeover", 2, device_id="unknown-device-009", mfa_verified=False),
            event("emp-009", "eval-takeover", 3, category="file_access", resource_category="confidential", file_count=450, sensitive_file_count=400, data_mb=800.0, device_id="unknown-device-009", mfa_verified=False),
        ]),
        case("abnormal-file-volume", "anomalous", "sensitive_access_volume", [
            event("emp-010", "eval-volume"),
            event("emp-010", "eval-volume", 3, category="file_access", resource_category="confidential", file_count=600, sensitive_file_count=500, data_mb=900.0),
        ]),
        case("external-transfer", "anomalous", "unapproved_destination", [
            event("emp-011", "eval-transfer"),
            event("emp-011", "eval-transfer", 2, category="data_transfer", destination="https://unapproved.example/upload", resource_category="confidential", data_mb=400.0, authorized_role=False),
        ]),
        case("unapproved-privilege", "anomalous", "privilege_policy_violation", [
            event("emp-012", "eval-unapproved-admin"),
            event("emp-012", "eval-unapproved-admin", 1, category="privilege_change", privilege="admin", authorized_role=False),
        ]),
        case("sensitive-file-burst", "anomalous", "sensitive_file_frequency", [
            event("emp-013", "eval-sensitive-burst"),
            event("emp-013", "eval-sensitive-burst", 1, category="file_access", resource_category="confidential", file_count=220, sensitive_file_count=210, data_mb=100.0),
        ]),
        case("admin-sequence", "anomalous", "unusual_admin_sequence", [
            event("emp-014", "eval-admin-sequence", device_id="unknown-device-014", mfa_verified=False),
            event("emp-014", "eval-admin-sequence", 1, category="admin_action", privilege="admin", device_id="unknown-device-014", mfa_verified=False, authorized_role=False),
            event("emp-014", "eval-admin-sequence", 2, category="privilege_change", privilege="admin", device_id="unknown-device-014", mfa_verified=False, authorized_role=False),
        ]),
        case("corroborated-after-hours", "anomalous", "unusual_login_context", [
            event("emp-015", "eval-off-hours", timestamp=heldout.replace(hour=2).isoformat(), category="auth_failure", failed_attempts=8, device_id="unknown-device-015", region="APAC", mfa_verified=False),
            event("emp-015", "eval-off-hours", timestamp=heldout.replace(hour=2, minute=2).isoformat(), device_id="unknown-device-015", region="APAC", mfa_verified=False),
        ]),
    ]
    return {
        "seed": seed,
        "generated_at": reference.astimezone(timezone.utc).isoformat(),
        "tenant_id": TENANT,
        "synthetic": True,
        "identities": identities,
        "training": training,
        "evaluation": evaluation,
        "split": {
            "training": "normal-only history; 30 rows per identity; ends at least two days before held-out activity",
            "evaluation": "separate labelled cases; not fitted or automatically learned",
            "training_count": len(training),
            "evaluation_case_count": len(evaluation),
        },
    }

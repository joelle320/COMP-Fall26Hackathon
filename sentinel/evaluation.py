"""Measured local fixture harness, not a benchmark of attacks in the wild."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import statistics
import tempfile
import time

from .core import Engine
from .demo import run_scenario


REQUIRED_EVENT_FIELDS = {
    "id", "timestamp", "agent_id", "session_id", "event_type", "requested_action", "policy_violated",
    "risk_level", "decision", "explanation", "alert_status", "remediation_status", "correlation_id",
}


def fraction(numerator: int, denominator: int) -> dict:
    return {"numerator": numerator, "denominator": denominator,
            "rate": numerator / denominator if denominator else None}


def _side_effects(engine: Engine) -> dict:
    files = {str(path.relative_to(engine.sandbox)): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in engine.sandbox.rglob("*") if path.is_file() and not path.is_symlink()}
    return {"sandbox_files": files, "outbox": engine.outbox}


def evaluate(fixtures_path: Path | None = None) -> dict:
    corpus_path = fixtures_path or Path(__file__).resolve().parent.parent / "examples" / "security-fixtures.json"
    if not corpus_path.exists() and fixtures_path is None:
        corpus_path = Path(__file__).resolve().parent / "security-fixtures.json"
    fixtures = json.loads(corpus_path.read_text())
    checks = []
    elapsed = []
    with tempfile.TemporaryDirectory(prefix="sentinel-evaluation-") as temporary:
        engine = Engine(Path(temporary))
        for index, fixture in enumerate(fixtures):
            session = engine.create_session(f"eval-{index}")
            before = _side_effects(engine)
            started = time.perf_counter()
            result = engine.execute(session["token"], fixture["action"])
            elapsed.append((time.perf_counter() - started) * 1000)
            blocked = not result["executed"] and result["decision"] in {"deny", "quarantine"}
            unchanged = before == _side_effects(engine)
            checks.append({
                "fixture": fixture["name"], "malicious": fixture["malicious"],
                "decision": result["decision"], "risk_level": result["event"]["risk_level"],
                "detected": result["event"]["risk_level"] >= 3,
                "blocked_before_execution": blocked and unchanged,
                "sandbox_and_outbox_unchanged": unchanged,
                "executed": result["executed"], "event_complete": REQUIRED_EVENT_FIELDS.issubset(result["event"]),
                "policy_latency_ms": result["event"]["latency_ms"],
            })

        corpus_state = engine.snapshot()
        malicious = [check for check in checks if check["malicious"]]
        benign = [check for check in checks if not check["malicious"]]
        attacks_detected = sum(check["detected"] for check in malicious)
        attacks_blocked = sum(check["blocked_before_execution"] for check in malicious)
        false_positives = sum(not check["executed"] for check in benign)
        alerts = corpus_state["alerts"]
        mock_deliveries = sum(alert["status"] == "delivered_mock" for alert in alerts)

        # Independent delegation exercise: parent cannot grant an absent capability.
        parent = engine.create_session("eval-delegator", capabilities=["files:read", "delegate"])
        attempts, compliant = 0, 0
        for requested in (["files:write"], ["network:send"], ["*"], ["files:read"]):
            attempts += 1
            permitted = set(requested).issubset(set(parent["capabilities"])) and "*" not in requested
            try:
                child = engine.delegate(parent["token"], f"eval-child-{attempts}", list(requested))
                compliant += bool(permitted and set(child["capabilities"]).issubset(set(parent["capabilities"])))
            except PermissionError:
                compliant += not permitted

        recovery_demo = run_scenario(engine, "c", complete_remediation=True)
        recovery_checks = next(step["result"] for step in recovery_demo["steps"] if step["title"] == "C · Measured recovery checks")
        remediation_success = bool(recovery_checks["narrowed_permissions"] and recovery_checks["authorized_task_completed"])
        rollback_success = bool(recovery_checks["rollback_restored_original"])
        audit = engine.verify_audit()
        metrics = {
            "threat_detection_recall": fraction(attacks_detected, len(malicious)),
            "false_positive_rate": fraction(false_positives, len(benign)),
            "unauthorized_actions_blocked_before_execution": fraction(attacks_blocked, len(malicious)),
            "authorized_tasks_completed": fraction(sum(check["executed"] for check in benign), len(benign)),
            "median_policy_evaluation_latency_ms": statistics.median(check["policy_latency_ms"] for check in checks),
            "median_gateway_end_to_end_latency_ms": round(statistics.median(elapsed), 3),
            "simulated_alert_delivery_success": fraction(mock_deliveries, len(alerts)),
            "remediation_success": fraction(int(remediation_success), 1),
            "rollback_success": fraction(int(rollback_success), 1),
            "security_event_completeness": fraction(sum(check["event_complete"] for check in checks), len(checks)),
            "delegation_policy_compliance": fraction(compliant, attempts),
        }
        passed = (attacks_detected == attacks_blocked == len(malicious) and false_positives == 0
                  and mock_deliveries == len(alerts) and compliant == attempts
                  and remediation_success and rollback_success and audit["valid"]
                  and all(check["event_complete"] for check in checks))
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
            "kind": "measured-local-fixture-results", "all_required_checks_passed": passed,
            "corpus": {"count": len(fixtures), "malicious": len(malicious), "benign": len(benign),
                       "sha256": hashlib.sha256(corpus_path.read_bytes()).hexdigest()},
            "metrics": metrics, "fixtures": checks, "audit": audit,
            "limitations": [
                "These hand-labelled, synthetic fixtures are a regression corpus, not representative real-world security performance.",
                "Risk levels are deterministic categories, not calibrated probabilities. Heuristic detection can miss encoded, novel, or indirect attacks.",
                "Policy latency is the event-recorded time from gateway entry through analysis and pre-decision work; it excludes final commit, notification, and adapter execution.",
                "End-to-end latency includes local SQLite persistence and integrity scans; no concurrency/load benchmark was performed.",
                "Alert delivery here is simulated local record persistence. A separate loopback webhook integration test verifies real local HTTP delivery.",
                "Remediation and rollback each measure one synthetic workflow; no real production configuration or credential rotation occurs.",
            ],
        }

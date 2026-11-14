from sentinel.core import Engine
from sentinel.demo import run_scenario
from sentinel.evaluation import evaluate


def test_four_attack_scenarios_complete_with_explicit_sandbox_authority(tmp_path):
    engine = Engine(tmp_path)
    result = run_scenario(engine, "all", complete_remediation=True)
    assert result["passed"]
    assert len(result["runs"]) == 4
    assert all(run["passed"] for run in result["runs"])
    assert engine.verify_audit()["valid"]


def test_dashboard_misconfiguration_demo_leaves_real_human_approval_pending(tmp_path):
    engine = Engine(tmp_path)
    run_scenario(engine, "c", complete_remediation=False)
    state = engine.snapshot()
    assert state["remediations"][0]["status"] == "proposed"
    assert state["approvals"][0]["status"] == "pending"
    assert "*" in state["agents"][0]["capabilities"]


def test_measured_fixture_harness_includes_observed_denominators():
    result = evaluate()
    assert result["all_required_checks_passed"]
    assert result["corpus"]["malicious"] == 12
    assert result["corpus"]["benign"] == 8
    assert result["metrics"]["threat_detection_recall"]["denominator"] == 12
    assert result["metrics"]["false_positive_rate"]["numerator"] == 0
    assert result["metrics"]["median_gateway_end_to_end_latency_ms"] > 0

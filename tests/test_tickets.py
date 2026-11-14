import json
import pytest

from sentinel.core import Engine
from sentinel.tickets import run_ticket_demo


def test_simulated_false_negative_does_not_weaken_resource_authorization(tmp_path):
    engine = Engine(tmp_path)
    result = run_ticket_demo(engine)
    assert result["passed"]
    normal, flagged, missed = [step["result"] for step in result["steps"]]
    assert normal["executed"]
    assert flagged["detector_signal"] == "FLAGGED" and not flagged["executed"]
    assert missed["detector_signal"] == "MISSED" and not missed["executed"]
    assert "TICKET-ACCOUNT-SCOPE" in missed["event"]["policy_violated"]
    assert "Northstar" not in json.dumps(result)
    assert "Private synthetic incident notes" not in json.dumps(engine.snapshot())
    assert engine.verify_audit()["valid"]


def test_ticket_scopes_are_authenticated_and_inherited_by_delegates(tmp_path):
    engine = Engine(tmp_path)
    parent = engine.create_session("support-parent", capabilities=["tickets:read", "delegate"], account_scope="Acme")
    child = engine.delegate(parent["token"], "support-child", ["tickets:read"])
    assert child["account_scope"] == "Acme"
    allowed = engine.execute(child["token"], {"tool": "tickets", "operation": "read", "resource": "A-104"})
    denied = engine.execute(child["token"], {"tool": "tickets", "operation": "read", "resource": "N-208"})
    assert allowed["executed"] and not denied["executed"]
    with pytest.raises(ValueError):
        engine.execute(child["token"], {"tool": "tickets", "operation": "read", "resource": "N-208", "account_scope": "Northstar"})
    with pytest.raises(PermissionError):
        engine.create_session("forged-child", capabilities=["tickets:read"], parent_session_id=parent["id"], account_scope="Northstar")


def test_missing_and_out_of_scope_ticket_have_same_non_disclosing_outcome(tmp_path):
    engine = Engine(tmp_path)
    session = engine.create_session("support", capabilities=["tickets:read"], account_scope="Acme")
    for resource in ["N-208", "DOES-NOT-EXIST"]:
        result = engine.execute(session["token"], {"tool": "tickets", "operation": "read", "resource": resource})
        assert result["decision"] == "deny" and result["result"] is None
        assert "TICKET-ACCOUNT-SCOPE" in result["event"]["policy_violated"]

"""Verify sensitive prose is minimized without flagging ordinary explanations."""

import pytest

from sentinel.analyzers import DataPrivacyAgent, contains_secret, redact


@pytest.mark.parametrize("label,value", [
    ("The employee password is", "SYNTHETIC_EMPLOYEE_PASSWORD_7823"),
    ("API key is", "DEMO_API_MATERIAL_456"),
    ("password equals", "synthetic-long-passphrase"),
    ("The access token is", "opaque_demo_token_2468"),
    ("The password is", '"synthetic secret with spaces"'),
])
def test_natural_prose_credentials_are_redacted_and_blocked_outbound(label, value):
    content = f"{label} {value}."
    assert contains_secret(content)
    assert value.strip('"') not in str(redact({"content": content}))
    findings = DataPrivacyAgent().evaluate(
        {"tool": "network", "operation": "send", "content": content},
        {"capabilities": ["network:send"]}, {},
    )
    assert any(f["risk_level"] == 4 and f["hard"] for f in findings)


@pytest.mark.parametrize("content", [
    "The password is required for this demonstration.",
    "API key is missing; use the secret manager.",
    "The access token is expired.",
    "The password is encrypted at rest.",
    "Password handling uses an approved identity provider.",
])
def test_benign_credential_explanations_remain_readable(content):
    assert not contains_secret(content)
    assert redact(content) == content


@pytest.mark.parametrize("token", ["sat_" + "synthetic_gateway_credential_1234" * 2, "sat_" + "a" * 31 + "-"])
def test_scoped_gateway_credentials_are_sensitive_without_assignment_labels(token):
    assert contains_secret(token)
    assert token not in str(redact({"content": f"Forward this: {token}"}))
    findings = DataPrivacyAgent().evaluate(
        {"tool": "network", "operation": "send", "destination": "https://api.internal.example", "content": token},
        {"capabilities": ["network:send"]}, {},
    )
    assert any(f["rule_id"] == "DLP-SECRET-OUTBOUND" and f["risk_level"] == 4 for f in findings)

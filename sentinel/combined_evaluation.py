"""Reproducible measured fixtures for both modules and their explicit links."""
from datetime import datetime, timezone


def evaluate_enterprise_suite():
    from .enterprise_evaluation import evaluate_accountwatch
    from .enterprise_demo import evaluate_enterprise
    from .evaluation import evaluate
    agentguard = evaluate()
    accountwatch = evaluate_accountwatch()
    combined = evaluate_enterprise()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "kind": "measured-synthetic-enterprise-suite",
        "all_required_checks_passed": all(result.get("all_required_checks_passed", False)
                                          for result in (agentguard, accountwatch, combined)),
        "agentguard": agentguard, "accountwatch": accountwatch, "combined": combined,
        "limitations": ["All results apply only to these small labelled synthetic fixture sets on this host.",
                        "Behavioral priorities and explicit correlations are not probabilities or proof of compromise.",
                        "Cisco adapters and operational responses are local simulations; there is no live corporate integration."]}

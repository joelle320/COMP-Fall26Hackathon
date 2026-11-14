# AccountWatch evaluation methodology

Read generated JSON evidence alongside any quoted metric. This document defines the intended interpretation and does not claim a result before the reproducible harness completes.

## Separate baseline fitting and evaluation

`sentinel/synthetic.py` produces synthetic employee/service identities, normal training observations and independently labelled held-out cases. The generator uses a fixed random seed and accepts a reference time for exact timestamp reproduction. Normal history ends before the held-out cases. Ground-truth labels belong to evaluation cases and are never accepted in the live event schema or used to fit a profile. Ingested attacks and analyst review outcomes do not automatically retrain the baseline.

The seeded profile uses compact per-identity histories and role comparisons instead of storing thousands of independent audit mutations. This is a fixture-scale regression design, not a representative enterprise log corpus. Neither a high metric on known examples nor a perfect synthetic correlation score establishes real-world security performance.

## Measurements

| Measurement | Interpretation |
| --- | --- |
| Anomaly precision | Labelled anomalous held-out cases correctly flagged / all flagged held-out cases at the harness threshold |
| Anomaly recall | Correctly flagged labelled anomalous held-out cases / all labelled anomalous cases |
| False-positive rate | Benign held-out cases flagged at that threshold / all benign held-out cases |
| Detection latency | Measured local event-analysis/ingest timing with its exact scope and units stated in the report |
| Benign exception handling | Expected approved travel/after-hours cases avoiding unnecessary escalation / applicable labelled exception cases |
| Correlation accuracy | Correct explicit-identity/session association decisions, including unrelated negative cases / correlation decisions checked |
| Analyst review completion | Review workflow assertions that completed with durable state / attempted assertions |
| Time to alert | Observed event-receipt/analysis-to-local-alert interval; not delivery to a live corporate service |
| Unnecessary interruptions | Benign supported workflows paused or blocked in the tested sample, with the denominator shown |
| Authorized workflow completion | Supported authorized tasks that actually completed / applicable tested tasks |

Use the exact report's score threshold and definitions. A low-priority contextual observation can differ from an anomaly requiring review; do not substitute frontend color counts for the harness's labels. Risk values are ordinal priorities, not calibrated probabilities. Macro case outcomes must not be presented as event-level precision without the appropriate denominator.

Original AgentGuard evaluation remains available separately with its existing 20-fixture corpus and explicit side-effect checks. It measures blocked attempts, legitimate completions, false-positive/noncompletion rate, local latency, mock alerts, synthetic remediation, rollback, event completeness and delegation scope compliance. See the [original evaluation guide](evaluation.md).

## Reproduction

From an installed source checkout, run commands separately:

```bash
.venv/bin/python -m pytest -q
```

```bash
.venv/bin/python -m sentinel evaluate --output work/agentguard-evaluation.json
```

```bash
.venv/bin/python -m sentinel enterprise-evaluate --output work/enterprise-evaluation.json
```

```bash
.venv/bin/python -m sentinel enterprise-demo --phase all --approve-sandbox-recovery --output work/enterprise-demo.json
```

The approval flag explicitly simulates the administrator role in the local CLI. Dashboard/HTTP demonstrations leave response and remediation approval to the human operator. No production account, credential or policy is changed.

Root verification records the actual automated-test count, generated measured results, production frontend build and any incomplete checks. A TypeScript build, served-bundle/API check and protocol test do not constitute visual browser QA. If browser-control infrastructure is unavailable, the report must say so. No browser or live Cisco verification is inferred from the design references.

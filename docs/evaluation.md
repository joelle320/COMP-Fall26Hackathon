# Reproducible evaluation

Run from the repository's activated Python environment:

```bash
pytest -q
python -m sentinel demo --output work/demo.json
python -m sentinel evaluate --output work/evaluation.json
```

The demo uses synthetic data and a temporary directory unless a data directory is explicitly supplied. Each scenario creates fresh session IDs. The evaluation reads `examples/security-fixtures.json`, currently 20 labelled cases: 12 malicious and 8 benign. Its report includes a corpus hash, Python version, case outcomes and denominators; no target is presented as a measurement.

## How to read measurements

| Measurement | Meaning in this MVP |
| --- | --- |
| Threat detection recall | Malicious fixtures receiving risk level ≥3 / the 12 labelled malicious fixtures. |
| False-positive rate | Benign fixtures with `executed=false` / the 8 labelled benign fixtures. This conservative noncompletion measure also counts adapter failure; it is not limited to malicious classification. |
| Unauthorized actions blocked | Malicious fixtures denied/quarantined with `executed=false` and unchanged sandbox-file hashes and outbox / the 12 malicious fixtures. Security records and containment state may change. |
| Authorized completion | Benign fixtures with `executed=true` / the 8 labelled benign fixtures. |
| Median policy latency | Median event-recorded milliseconds from gateway entry through analysis and pre-decision work. Excludes final commit, notification and adapter execution. |
| Median gateway latency | Median caller-measured `Engine.execute` wall time including local persistence, integrity scans, notification and adapter work; no load/concurrency benchmark. |
| Alert delivery | Corpus alerts with status `delivered_mock` / all corpus alerts. Real loopback webhook delivery is tested separately, outside this metric. |
| Remediation success | One scenario-C workflow: narrowed permissions and a successful authorized read / one attempted workflow. |
| Rollback success | Exact original synthetic capability configuration restored / one attempted workflow. |
| Event completeness | Corpus events containing the harness's 13 required incident fields / all 20 corpus events. |
| Delegation compliance | Correct allow/deny outcomes for four requests: absent file-write, absent network-send, wildcard, and permitted file-read. Broader ancestry/containment properties belong to the security tests, not this four-request metric. |

The required completeness fields are `id`, `timestamp`, `agent_id`, `session_id`, `event_type`, `requested_action`, `policy_violated`, `risk_level`, `decision`, `explanation`, `alert_status`, `remediation_status` and `correlation_id`. Completeness checks presence, not the correctness of every value.

The generated report is the authority for the exact definitions and counts used by that version of the harness. Keep its configuration, fixture details and environment information alongside any quoted result. A local mock notification is not a delivered Slack/Teams/SIEM message. A successful synthetic configuration validation is not proof of host or credential recovery. The final audit check includes the corpus plus the delegation and recovery exercise.

## Security properties

The suite should inspect adapter effects, rather than only asserting a decision label. Important cases include a blocked send leaving the outbox unchanged, a blocked file write leaving content unchanged, plaintext synthetic keys absent from events/results/alerts, unauthenticated and agent credentials failing authority routes, approval replay and changed payloads failing, children not acquiring missing scope, ancestor containment taking effect, and audit/persistence failures preventing execution.

The corpus is deliberately small and deterministic. It does not estimate performance on arbitrary repositories, models, languages, encodings or adversarial strategies. Pattern detection has false negatives and may reject legitimate quoted security material. Report measured results with this limitation, retain failed cases, and resolve verified defects before reporting success.

Browser tooling was unavailable in the supplied environment. Production TypeScript/build, bundle-serving checks and API tests verify their respective layers, but the dashboard has not been visually or interactively verified in a browser here.

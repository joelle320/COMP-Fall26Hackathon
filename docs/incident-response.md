# Incident response and human review

All examples use synthetic sessions and project configurations. SENTINEL does not modify production systems or rotate organizational credentials.

## Risk and outcomes

| Level | Meaning | Default outcome |
| --- | --- | --- |
| 0 — informational | Expected, authorized behavior | Allow and record relevant metadata. |
| 1 — low | Unusual but likely legitimate | Allow with a finding / monitoring. |
| 2 — moderate | Sensitive supported change requiring authority | Pause and create a pending approval. |
| 3 — high | Strong evidence of a policy violation | Deny, record a sanitized incident and alert. |
| 4 — critical | Secret exfiltration or strong compromise evidence | Block and quarantine the affected session; require authority review before restoration. |

Risk levels are ordinal explanations, not calibrated probabilities. Mandatory policy controls take precedence over risk scoring and approval.

## Operator workflow

1. Connect the dashboard with the locally generated authority token. Use an agent token only with gateway or delegation endpoints.
2. Open an incident and inspect its agent/session, correlation ID, requested action, policy IDs, module findings and safe alternative. Raw credentials and unnecessary PII are omitted.
3. Review the affected session and its parent/children. Quarantine applies to the session; ancestry checks also prevent descendants from continuing under a quarantined ancestor.
4. Propose a least-privilege remediation. The proposal captures the original synthetic capability configuration, recommended capabilities, reason and approval ID.
5. Approve or reject the exact proposal as the organizational authority. A protected agent cannot call authority routes or approve itself.
6. Apply an approved proposal. Inspect the recorded validation result before continuing.
7. Restore the session only after an authorized review note and required recovery validation. A successful configuration change does not automatically restore it.
8. If the change needs reversal, use the authority rollback action. The original configuration is restored and the outcome recorded; rollback does not bypass quarantine or hard policy rules.

For an actual credential incident, the safe response is to stop the transfer, notify authorized personnel and use the organization's approved secret manager. This MVP's sandbox remediation never rotates a real credential.

## Approval versus permission

A tool approval authorizes one supported action, bound to its requesting session and exact content fingerprint. It expires and is consumed on execution. It cannot grant a missing capability, approve a different payload, override a destination restriction or authorize a prohibited secret transfer. Rejected or expired requests require a fresh review.

The dashboard scenario C intentionally stops at a proposed least-privilege fix. An operator must approve and apply it. The CLI demonstration can exercise approval and rollback as an explicit synthetic authority action; that behavior is limited to the isolated demonstration, not autonomous incident handling.

## Appeals and false positives

Use the incident review action to record a meaningful explanation and correlation ID. An appeal changes review history; it does not erase evidence or grant permission. For example, a repository may legitimately quote an injection phrase for a security test. Keep that text as test data, remove it from the instruction channel, and resubmit the legitimate operation with untrusted provenance intact. An authorized policy owner may revise a rule after reviewing the false positive; the protected agent cannot do so.

## Safe alternatives

The gateway returns an explanation and safe alternative for blocked actions. Examples include using synthetic credentials, reading an approved non-sensitive project file, limiting a delegated capability scope, or routing a secret operation through an approved secret-management interface. The redirection is guidance; the gateway evaluates the next action independently.

## Notifications and evidence

High and critical incidents create sanitized notifications for the simulated security channel. A successful mock delivery means the local demonstration adapter persisted a notification. It does not mean Slack, Teams or a SIEM accepted it. The configurable loopback webhook adapter supports testing real local HTTP delivery, with `siem`, `slack` and `teams` payload formats selected by `--webhook-adapter` or `SENTINEL_WEBHOOK_ADAPTER`. Live corporate endpoint integration requires separate authorization and testing beyond this local-only MVP.

The audit endpoint checks integrity. If it fails, tool execution stops. Preserve the local database and integrity material for diagnosis through an authorized process; do not delete evidence to resume a session. The MVP's local chain cannot establish integrity against an attacker who controls all local files and the service process.

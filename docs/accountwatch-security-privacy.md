# AccountWatch security and privacy

AccountWatch is a synthetic security investigation prototype. It is designed to identify review-worthy deviations while preserving the distinction between observed activity, inferred risk, and confirmed policy violations. It is not an employee productivity monitor, a lie detector, or evidence of malicious intent.

## Data minimization and purpose

Ingest accepts a bounded typed allowlist: pseudonymous identity and authentication-session identifiers, timestamp, event category, application/resource category, device label, coarse region, file/access counts, session duration, failures, privilege context, destination context, and approved exception/verification flags. Unknown fields and malformed or unbounded values are rejected. Caller-provided familiarity cannot replace baseline evidence. Authentication-session ownership cannot be reassigned across identities.

The demonstration contains 20 synthetic employees and three synthetic service identities across multiple job roles. No real employee data is needed. Do not send passwords, tokens, private messages, browser histories unrelated to security, screenshots, audio, video, keystrokes or sensitive personal characteristics. The service neither collects those surveillance sources nor recommends disciplinary action. Free-form analyst notes are minimized and redacted, but should still avoid unnecessary personal or credential details.

Real deployment would require an authorized security-monitoring purpose, appropriate organizational notice, consent or another applicable lawful authorization, documented access rights, retention review, and a process for employees to challenge inaccurate evidence. Synthetic demo operation does not establish compliance with those obligations.

## Roles and trust

| Role | Permitted work | Excluded authority |
| --- | --- | --- |
| Administrator | Provision linked agents, seed synthetic data, run demonstrations, approve eligible repairs and scoped responses, authorize mock step-up/restoration and retention purge | Cannot approve away mandatory tool/data/account constraints |
| Analyst | Read AccountWatch and Command evidence, ingest allowed synthetic metadata, mark expected behavior, escalate, request verification, propose scoped containment, close/reopen and record notes | Cannot provision agents, apply containment, approve privileged repair, edit policy or restore agents |
| Protected agent | Request its scoped gateway operations and permitted delegation | Cannot inspect employee analytics, review incidents, approve itself, replace identity bindings or modify organizational policy |

Credentials are distinct local bearer tokens. The browser holds the entered credential in memory rather than local storage or cookies. A supplied reviewer label does not create an employee identity or another permission grant. Local administrator/analyst credentials are an MVP role model, not organizational SSO or personal attribution. Keep the service on loopback and protect the local data directory.

## Explainability and proportionate response

Default visual priority bands are informational 0–24, low 25–49, moderate 50–69, high 70–89 and critical 90–100. They are configurable backend policy, not risk probabilities or proof of compromise. Personal median/MAD ranges, role context, reason codes and event sequences support every score. Differences between job roles are normal; a role baseline is context rather than an accusation.

Known approved travel or verified after-hours work can explain a deviation. A low-signal unusual hour alone does not trigger broad access removal. An analyst can mark evidence expected, and close/reopen or escalate a case. Review history remains visible. An expected/closed annotation does not erase a hard AgentGuard policy or authorize unrelated future actions.

A response proposal identifies one synthetic identity and authentication session. Administrator approval can request step-up or restrict that session; it does not disable the employee's whole account. Mock verification is explicit and time bounded. Linked sensitive agent actions may require additional approval, while unrelated permissions and identities remain unchanged. Repairs preserve the original synthetic agent configuration for rollback and require separate approval, validation, and reviewed restoration.

## Retention and audit scope

The AccountWatch backend policy exposes `retention_days` (default 30), `baseline_retention_days` (default 90), minimum baseline samples, the correlation window, review/step-up thresholds, and short verification lifetime. Read the active policy in the dashboard and inspect `AccountWatch.purge_expired()` before claiming broader deletion behavior.

The purge operation replaces expired `aw_event` records with minimal tombstones and removes copied detailed reasons from expired anomaly records. It expires baseline details after `baseline_retention_days` measured from baseline creation, and removes authentication-session detail once its expiry is older than the activity retention cutoff. Raw event, anomaly-evidence, baseline-history and authentication-session detail snapshots are minimized before entering the historical audit chain; retained state digests continue to protect live records from modification. Minimal lifecycle identifiers, timestamps, reason codes, scores, review/response state, integrity digests and operational records can remain after detail expiry. This is logical application-level expiry, not forensic secure erasure of SQLite pages, backups, every derived datum or analyst note.

The current prototype does not automatically schedule retention. An administrator invokes the authenticated retention-purge endpoint. Expired baseline profiles require trusted re-provisioning before further analytics; observed attack traffic must not become replacement training data. Human investigation notes, response records and minimal ownership/lifecycle evidence have a separate operational lifecycle and are not removed by telemetry purge. Before production, validate per-record-class expiry, legal holds, note retention and deletion/backup handling appropriate to the organization.

The audit chain has a keyed local integrity anchor. It detects database record alteration or truncation under its trust assumptions, but a process/OS administrator controlling the key and all state can forge local history. It is not a remote immutable archive. A failed integrity check prevents protected tool execution and analytics mutation. One process/worker per local data directory is supported.

## Configuring the analytics policy

Add an `accountwatch` object to the trusted organizational policy JSON passed through `--policy`. It merges with bounded backend defaults. For example:

```json
{
  "accountwatch": {
    "retention_days": 30,
    "baseline_retention_days": 90,
    "min_samples": 10,
    "correlation_window_minutes": 30,
    "review_score": 50,
    "step_up_score": 70,
    "verification_minutes": 15
  }
}
```

Merge this illustration into the complete AgentGuard policy; preserve its destination, capability and resource constraints. Custom risk `thresholds` must provide five unique supported labels in contiguous bands covering 0–100. Trusted policy changes require administrator file access and a service restart; the analyst dashboard has no policy-write endpoint. Review thresholds against the separate held-out fixture corpus and real authorized operating context before using them beyond the demonstration.

## Threat and failure boundaries

Attacker-controlled documents and agent text cannot replace token identity, inheritance rules, organizational policy, or mandatory authorization. A predefined simulated detector miss is safe in the ticket demonstration because the executor checks the bound account independently. Behavioral risk cannot grant capabilities or weaken exfiltration prevention.

An anomaly is an inference from limited metadata; attackers can imitate normal patterns, omit context, encode secrets, or exploit uncovered behavior. A compromised trusted telemetry source can falsify reported context. This MVP has no assurance of complete real-world logs, calibration, secure endpoint attestation, large-scale capacity, production token revocation or validated Cisco enforcement integration.

If initial decision persistence fails, the adapter does not run. If an authorized side effect succeeds but completion persistence fails, its pending state means completion is unconfirmed; investigate before retrying. Local notification failures are recorded and do not permit a blocked tool operation. See the [original threat model](threat-model.md) and [enterprise architecture](enterprise-architecture.md).

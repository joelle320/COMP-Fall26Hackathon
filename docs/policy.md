# Policy configuration

`policies/default.json` is the local organizational policy; a packaged copy provides the installed module's default when the source file is absent. Supply another JSON file using `python -m sentinel serve --policy path/to/policy.json`. An explicitly missing policy file or malformed configuration fails startup. Policy is loaded by the trusted service, outside protected-agent file adapters. An untrusted document cannot update it. Restart the local service after a reviewed policy-file change; there is no agent-controlled policy mutation route.

## Destinations and classifications

`destinations` is an exact HTTPS-origin allowlist. The sample permits `https://api.internal.example` and `https://siem.internal.example`; those are labels for the mock outbound adapter, not live services. User information, malformed authorities, unsupported schemes and unapproved origins are rejected. Paths may vary within an allowed origin. A hostname suffix match is not sufficient. `destination_allowlist` is a compatibility alias in the sample; keep both consistent when editing, with `destinations` taking precedence.

An allowed destination does not authorize sensitive content. Outbound recognized credentials, personal information and confidential classifications remain prohibited. The `classifications` object adds case-insensitive regular-expression patterns under `secret_patterns`, `pii_patterns` and `confidential_patterns`; these feed both detection and redaction, while built-in detectors continue to apply. Invalid regular expressions fail startup. Sample business classifications include “confidential,” “INTERNAL-ONLY” and “trade secret.” Pattern matching is configurable evidence, not comprehensive DLP or a semantic guarantee.

For example, an organizational policy can add a synthetic customer identifier without storing real customer data:

```json
{
  "classifications": {
    "secret_patterns": [],
    "pii_patterns": ["\\bCUSTOMER-[0-9]{8}\\b"],
    "confidential_patterns": ["\\bINTERNAL[- ]ONLY\\b"]
  }
}
```

Merge such fields into a complete policy rather than replacing the default policy with this partial illustration. Classification patterns are trusted administrator configuration and must be reviewed and tested before use.

## Capabilities and resources

`default_capabilities` supplies new sessions' default scope, initially `files:read`, `files:write`, `network:send` and `delegate`. `allowed_capabilities` is the organizational ceiling intersected with the session and all ancestors' scope on each action. A session can receive a smaller set. Child scope must be a subset of its live parent's scope, with bounded expiry and delegation depth. A wildcard in a synthetic demo configuration produces a misconfiguration finding and remediation proposal; it cannot create a new execution adapter, exceed the organizational ceiling or override mandatory controls.

`critical_resources` identifies supported sensitive configuration paths such as `config/agent.json`. Writes require an exact expiring single-use approval. `protected_resources` identifies credential/authentication resources; built-in credential path checks also apply. File adapters remain confined to the project sandbox, reject escapes and symlinks, and cannot access policy, authority tokens or the database outside that boundary.

## Limits and mandatory controls

The `limits` object configures action/file sizes, session TTL, tool-approval TTL and delegation depth. Positive integer values are bounded by fixed implementation ceilings:

| Limit | Sample value | Fixed ceiling |
| --- | --- | --- |
| `max_action_bytes` | 65,536 bytes per field | 65,536; canonical total is bounded to twice the field limit. |
| `max_file_bytes` | 65,536 bytes | 65,536. |
| `max_session_ttl_seconds` | 3,600 seconds | 86,400; child expiry also cannot exceed the parent. |
| `approval_ttl_seconds` | 300 seconds | 900 for tool approvals. Remediation proposals separately expire after 900 seconds. |
| `max_delegation_depth` | 8 sessions in the chain | 8. |

The API independently caps incoming JSON at 128 KiB. Unsupported tools and operations fail closed even if a capability string is present. The gateway provides no arbitrary command execution adapter.

`mandatory_controls` describes controls implemented in code; deleting a descriptive string is not a mechanism for bypassing them. The five risk labels describe policy outcomes. Numeric levels are ordinal and uncalibrated; mandatory denials take precedence over scores, prose authorizations and human approvals.

## Local notification adapters

Set `--webhook-adapter siem|slack|teams` or `SENTINEL_WEBHOOK_ADAPTER` to choose a sanitized payload format. `siem` sends the structured incident object, `slack` wraps its canonical JSON in a `text` field, and `teams` uses a MessageCard envelope with summary and text. The selected format and delivery payload are recorded with each alert.

Without a webhook URL, delivery remains a persisted simulation. To test an actual local HTTP notification, configure an explicitly authorized mock receiver, for example:

```bash
python -m sentinel serve --webhook-url http://127.0.0.1:9001/security --webhook-adapter slack
```

The receiver must already be running. `SENTINEL_WEBHOOK_URL` is the URL alternative. Only loopback HTTP destinations (`127.0.0.1`, `localhost`, `::1`) are accepted, redirects are not followed, and delivery success/failure is recorded. These adapters demonstrate the three payload formats; live Slack, Teams and SIEM endpoint connectivity is outside this MVP.

To validate a policy change, run the automated suite and labelled evaluation corpus with the intended configuration, inspect false positives, verify destination parsing and redaction, and repeat the approved-task checks. Do not infer behavior on unseen encodings, languages or host integrations from the small fixture set.

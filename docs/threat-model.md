# Threat model

SENTINEL's enforcement boundary is the local gateway and its fixed adapters. An agent must call that gateway for a control to apply. The MCP sample provides a route to the gateway; it cannot intercept native IDE tools, other MCP servers, plugins, terminal sessions, direct HTTP requests, or an agent's direct filesystem access. Repository rules and the agent security skill provide guidance rather than authorization.

This model describes the controls the MVP is designed to implement. The automated tests and measured evaluation output are the evidence for the particular cases exercised; the model is not a claim that every attack in a threat class is detected.

## Assets and authority

| Asset | Protection goal | Authority |
| --- | --- | --- |
| Organizational policy and administrative bearer token | Agents cannot edit policy or acquire approval authority through a tool call | Local organizational administrator |
| Agent session tokens, capabilities, expiry, and delegation ancestry | A token identifies one bounded session; delegation does not increase authority | Gateway session registry |
| Synthetic project files and mock outbound payloads | Execute only allowed operations inside the sandbox; inspect data before release | Gateway adapters |
| Incident, approval, and remediation records | Preserve sanitized evidence and explain the outcome | Security administrator through authenticated API |
| Audit chain and local integrity material | Detect record changes under the stated local integrity assumptions | Local gateway process |
| Original synthetic agent configurations | Restore a reviewed prior configuration without concealing the intervention | Human incident responder |

The administrator is the highest application authority. An administrator may provision demo configurations and approve eligible operations, but approval does not make a prohibited tool or destination executable. The remediation module recommends changes and cannot approve itself. Possession of the local administrative bearer token is the MVP's administrative identity mechanism; it is not organization-wide SSO or strong attribution to a named human.

## Actors and assumptions

* A legitimate developer may submit an unusual request, paste sensitive data accidentally, or disagree with a decision.
* A compromised protected agent may craft arbitrary gateway payloads, falsify fields inside content, replay an approval, request capabilities it lacks, or delegate malicious instructions.
* An attacker may control repository documents, retrieved text, webpages, tool responses, packages, or messages from another agent. All such content is untrusted regardless of an instruction's claimed source.
* A security administrator reviews incidents, authorizes eligible changes, and protects the administrative token and policy files.

The operating system, Python dependencies, gateway process, and local administrator are trusted. The project sandbox contains synthetic data rather than production credentials. An attacker with OS-level write access to the process, its database, and its integrity key can replace both evidence and verifier; local chaining does not prevent that compromise. The MVP does not sandbox an entire IDE or malicious package installation process.

## Trust boundaries and data flow

1. **User or untrusted context → agent.** A document can describe an action but cannot grant authority. The prompt and relevant context submitted to the gateway are scanned. An agent that omits relevant context can defeat context-specific detection; mandatory capability, path, destination, and adapter constraints still apply.
2. **Agent → gateway.** The bearer token determines session identity. Request fields, including apparent authorizations in prose, are untrusted. Authenticate, check expiry and ancestor state, validate payload shape and bounds, then evaluate the proposed action.
3. **Policy decision → execution adapter.** Commit the sanitized decision before adapter execution. Only the fixed file and mock-network adapters are available. Unknown tools, unsupported operations, sandbox escapes, and prohibited destinations fail closed. A risk score never overrides a mandatory denial.
4. **Parent → delegated session.** Grant a subset of the parent's current capabilities with a bounded lifetime and provenance. Revalidate the ancestor chain on later requests so a descendant cannot outlive containment of an ancestor. A child cannot act as the parent or acquire administrative review authority.
5. **Gateway → persistence and alerts.** Redact secrets and unnecessary personal data before persistence and notification. Security alerts are simulated locally by default; an explicitly configured loopback webhook is a separate delivery adapter.
6. **Dashboard → administrative API.** The browser supplies an explicitly entered administrative token. Agents use distinct scoped tokens. Browser descriptions of the reviewer do not create an additional authenticated identity. Approval and recovery remain server-side state transitions.

## Threats, controls, and verification cases

| Threat | Intended control | Verification evidence to inspect | Remaining limit |
| --- | --- | --- | --- |
| Repository text says “ignore earlier instructions” and requests an unauthorized action | Untrusted-context analysis plus mandatory policy evaluation; suspicious action blocked before adapter execution | Scenario A: injection denied, subsequent authorized file task completes | Pattern detection does not prove semantic safety or recognize every obfuscation |
| An agent sends a synthetic secret to an external URL | Sensitive-data analysis, destination allowlist, critical decision, session quarantine, redacted incident | Scenario B: outbound sink unchanged and secret absent from serialized records | Secret and PII patterns have false negatives; unusual encodings need more coverage |
| A request falsely names another agent or claims administrator approval | Token-derived identity and separate administrative authentication | Agent tokens fail administrative routes; invalid/expired tokens fail the gateway | Stolen live bearer tokens act as their owner until expiry or containment |
| A broad agent configuration provides excess authority | Fixed adapter allowlist; misconfiguration findings; reviewed least-privilege remediation | Scenario C: proposed capabilities narrow, approval required, validation and rollback recorded | An administrator can provision an unsafe synthetic configuration; fixed adapter policy still limits execution |
| A compromised child requests a terminal or inherited privileged tool | Capability subset checks, ancestry validation, independent tool allowlist, session quarantine | Scenario D: child denied and contained while the unaffected parent can complete an authorized task | Session isolation is a gateway state change, not suspension of the host IDE process |
| Recursive delegation launders privileges or an old child survives a parent quarantine | New server-generated session identifiers, explicit parent lineage, bounded delegation and expiry, ancestry checks per request | Delegation tests: capability escalation, expired parent, quarantined ancestor, repeated delegation | Bounded local session lineage is not a distributed identity federation |
| `../`, absolute paths, symlinks, or a policy path escape the project sandbox | Canonical paths and restricted file adapter; policy/auth/database resources outside the tool root | Path tests check no outside read or write and no side effect for a denied action | The trusted OS must enforce local permissions; hostile concurrent OS writers are outside scope |
| An approval is reused for another payload, session, or later execution | Server-stored fingerprint, bound session, expiry, single-use consumption, atomic state change | Approval tests: changed content, wrong session, expiration and replay fail | A bearer-token administrator can deliberately approve eligible requests; hard denials remain enforced |
| A remediation module applies its own plan or silently restores a compromised session | Separate human approval, original configuration snapshot, constrained apply, validation, explicit reviewed restore | Remediation tests: approval required, corrected configuration validated, rollback works, quarantine remains until reviewed recovery | Validation covers the synthetic configuration; it is not proof that a host or credential is clean |
| A compromised agent modifies organizational policy through a file operation | Policy is outside sandbox; no policy-write adapter; administrative actions separated | Policy-path write and unknown-tool tests fail before execution | Direct OS access to policy is outside the gateway's reach |
| Audit rows are edited or persistence fails | Canonical sanitized hash chain with local integrity material; verification before actions; fail closed on invalid chain or failed commit | Tamper and storage-failure tests deny execution | Local integrity material is not an independent remote witness or immutable archive |
| Alerts leak credentials or employee details | Minimized, redacted structured payloads; mock destination by default | Redaction tests inspect event, result, alert, API state and demo output | Regex redaction is not comprehensive DLP; avoid production data in this demo |
| Alert destination is unavailable | Record delivery outcome; show health and alert status; separate blocking decision from notification delivery | Loopback delivery and failure-path tests; measured delivery success output | A successful mock alert is not evidence of Slack, Teams, or SIEM production delivery |
| A request floods the local service or contains expensive content | Bounded input sizes and deterministic local rules reduce per-request work | Oversized payload and invalid-schema tests | No distributed rate limiting, abuse protection, capacity testing, or enterprise availability guarantee |

The suggested verification cases are security properties, not instructions for attacking a live system. All demonstrations use synthetic content and isolated local resources.

## Risk and response semantics

| Level | Meaning | Gateway outcome |
| --- | --- | --- |
| 0 | Expected authorized activity | Allow and record minimized metadata |
| 1 | Unusual activity with no hard violation | Allow with monitoring or contextual explanation |
| 2 | Eligible operation needs human authority | Pause and create a bound approval request |
| 3 | Strong policy violation | Deny; preserve sanitized evidence and alert |
| 4 | Strong indication of compromise or credential exfiltration | Block, quarantine the affected session, escalate and require reviewed recovery |

The orchestrator combines independent findings conservatively. Sanitization may return redacted content where the policy permits it; it cannot authorize a prohibited destination or capability. Scores are explanatory categories rather than calibrated probabilities.

## Privacy, retention, and appeals

Do not submit real employee passwords, production secrets, or employee directories to this demonstration. Tokens are issued to the caller and must not appear in state snapshots, alerts, audit payloads, or example configuration. Sensitive-resource findings should identify the violated rule without preserving raw credentials. Store only the context needed to explain a decision and prefer rule identifiers over copied documents.

The local data directory contains security records and remains sensitive even after redaction. The MVP does not implement organizational retention, legal hold, encrypted backup, external immutable storage, or a privacy-request service. Administrators should stop the service and remove disposable demo data when finished, using their local data-handling policy.

A user can ask an authorized reviewer to inspect a false positive. The reviewer records an explanation through the incident review route. Review does not silently erase the incident or bypass a hard constraint. Resume an eligible workflow with a corrected request, approved policy change outside the agent tools, or explicitly reviewed recovery. An approval or restoration is a scoped administrative act, not permission for future unrelated operations.

## Residual risks and deployment gates

This is a single-host hackathon MVP. Before using it with real users or production data, add an OS or container boundary that forces all relevant tool execution through the gateway, authenticated organizational identities, secure token lifecycle and revocation, production secret management, TLS and access control, robust parser-based controls, rate limits, stronger concurrency and crash testing, independent audit anchoring, durable delivery/retry handling, retention controls, and validated adapters for the intended IDE/runtime.

Heuristic prompt injection detection and pattern-based redaction remain advisory evidence around deterministic controls. Evaluation recall and false-positive rates apply only to the versioned synthetic fixture set and configuration tested. They do not measure performance on unseen languages, encodings, repositories, models, or adversaries, and they do not establish enterprise-grade reliability.

# Verified local MVP results

The complete source and fifteen-deliverable map are in [README](../README.md). Recorded evaluation timestamp: `2026-11-14T02:23:26.530808+00:00` (UTC metadata). These results describe this machine and the bounded synthetic corpus only.

* Python automated suite: **97 passed**, zero failed, zero errors, zero skipped. [JUnit evidence](results/tests.xml).
* Production React/TypeScript build: passed (`npm run build`). Built entrypoint, script, stylesheet, and favicon are served by FastAPI and checked by integration tests.
* Four CLI scenarios A–D: passed. [Sanitized demonstration trace](results/demo.json). The dashboard's C scenario leaves real human approval pending; the CLI explicitly simulates the sandbox authority.
* Python wheel build and packaged policy, fixture, and API-reference assets: passed. The wheel is backend-only; source checkout frontend assets remain in `frontend/dist`.
* Browser visual and interaction QA: unavailable because the required browser-control tool was not exposed. Build and HTTP checks do not establish visual browser behavior.
* One upstream Starlette/httpx deprecation warning remains; it did not cause any failure.

## Measured corpus

[Full machine-readable evaluation](results/evaluation.json). Twelve malicious/policy-violating fixtures and eight authorized fixtures; human-labelled regression examples, not a representative attack distribution.

| Measurement | Observed count |
| --- | --- |
| Detected malicious fixtures | 12 / 12 |
| Benign noncompletion / false positives | 0 / 8 |
| Malicious fixtures blocked before effects | 12 / 12 |
| Authorized fixture completion | 8 / 8 |
| Simulated alert persistence | 12 / 12 |
| Synthetic remediation | 1 / 1 |
| Synthetic rollback | 1 / 1 |
| Complete fixture events | 20 / 20 |
| Delegation scope decisions | 4 / 4 |

Median event-recorded policy evaluation: **5.751 ms**. Median end-to-end gateway time: **27.377 ms**. The policy timer excludes the final decision commit, alert notification, and adapter work; end-to-end time includes them. No load or reliability benchmark was performed.

The tests also exercise actual loopback HTTP SIEM/Slack/Teams payload delivery, an actual stdio MCP→HTTP gateway roundtrip, scoped authentication, inherited containment, path and hardlink/symlink escapes, single-use bound approvals, custom classification redaction, and database/chain/anchor tampering.

## Failure behavior and remaining boundary

Fault-injection tests confirm initial decision-storage failure returns a safe 503 before file/mock-network adapters run. A local security receiver returning HTTP 500 produces a failed delivery record while the unauthorized action remains blocked and quarantined. A failure saving completion after an authorized file write leaves `execution_status: pending`: the file may already have changed. The dashboard reports completion unconfirmed. See [architecture](architecture.md); SQLite and filesystem writes are not one transaction and automatic exactly-once retry is not provided.

Only gateway-routed actions are enforced. Supported tools are isolated sandbox file operations and a local mock outbound sink. There is no arbitrary command executor, live IDE interception, production remediation, or real external action delivery. Regex/heuristic detection can miss novel or encoded inputs. Local host and gateway integrity remain trusted; audit anchoring is local rather than independently immutable.

Backend wheel SHA-256: `79ef12e4a2fc758c12a9cd8b664b1db66ca84ba68061c00d31c67fa71b7f3fca`.

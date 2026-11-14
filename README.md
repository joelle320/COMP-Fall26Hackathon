# SENTINEL — Enterprise Security Prototype

A functional local MVP for AI-agent security orchestration. SENTINEL evaluates proposed tool calls through an independent gateway, combines four deterministic security analyzers, blocks unauthorized actions before execution, records sanitized tamper-evident events, and supports human-approved synthetic remediation.

The React dashboard and CLI demonstrate prompt injection, synthetic credential exfiltration, excessive permissions and a compromised delegated agent. Python 3.12+, FastAPI, Pydantic, SQLAlchemy/SQLite and React/TypeScript are used. No LLM, enterprise security account or real credential is required.

**Enforcement scope:** only actions routed through SENTINEL's fixed adapters are protected. File operations run inside the synthetic sandbox; allowed outbound requests go to a local mock sink. Arbitrary shell execution is unsupported. MCP exposes the gateway; it does not intercept native IDE tools. Cursor-specific hooks have not been verified. See [architecture](docs/architecture.md) and [threat model](docs/threat-model.md).

## Enterprise enhancement

**AgentGuard** preserves the existing enforced agent-security workflow. **AccountWatch** adds metadata-only synthetic identity baselines, explainable contextual anomalies and analyst review. **SENTINEL Command** connects them through explicit identity/authentication-session/agent ownership and a unified investigation queue. Original AgentGuard navigation and A–D demonstrations remain available.

The attached AccountWatch video and Activity Lab guide the baseline/evidence presentation. The navy/cyan enterprise design retains SENTINEL branding and bundled typography. Cisco Duo, XDR, Secure Access, Identity Intelligence and Splunk are **proposed mock integration opportunities**; no official Cisco affiliation, product support or live integration is claimed.

The preserved fifth feature is now the support-ticket authorization comparison from the conversation: an Acme-bound agent cannot read the other account's ticket whether a predefined simulated detector flags or misses the instruction. Account authorization is enforced in the gateway. The simulated labels are not an AI accuracy benchmark.

Read the [implementation audit and plan](docs/enterprise-plan.md), [enterprise architecture/data flow](docs/enterprise-architecture.md), [AccountWatch security and privacy](docs/accountwatch-security-privacy.md), and [evaluation methodology](docs/accountwatch-evaluation.md). The [presentation script](docs/hackathon-script.md) walks normal operations → threat investigation → approved recovery.

## Run locally

Extract the ZIP and open the extracted `sentinel` folder in VS Code. The delivery includes `frontend/dist`, so starting the included dashboard does not require Node.js or a frontend rebuild. Python **3.12 or newer** is required. The cloud development path is not a path on your computer.

On macOS/Linux, open a terminal in that folder and run **each command separately**:

```bash
python3.12 --version
```

```bash
python3.12 -m venv .venv
```

```bash
.venv/bin/python -m pip install --upgrade pip
```

```bash
.venv/bin/python -m pip install -e ".[dev]"
```

```bash
.venv/bin/python -m sentinel serve
```

On Windows, create the environment with `py -3.12 -m venv .venv` and use `.\.venv\Scripts\python.exe` in place of `.venv/bin/python`. On a source checkout without built dashboard assets, install Node.js 20+ and run `npm ci` then `npm run build` in `frontend/`, return to the project folder and start the Python service. `uv sync --locked --extra dev` is an alternative locked Python installation.

Open **http://127.0.0.1:8000**. The server creates `.sentinel-data/admin.token` with owner-only permissions. Leave the server running. In a second terminal in the project folder, explicitly display the local authority credential:

```bash
.venv/bin/python -m sentinel token
```

Enter that token in the dashboard's local authority connection. The browser holds it in memory; reconnect after reloading. Session credentials are separate scoped tokens and cannot administer the service. The separate local analyst role can investigate but cannot approve privileged repairs or apply containment. A reviewer label is not organizational SSO or an independently authenticated employee identity.


To use the analyst role, obtain its separate local credential with `.venv/bin/python -m sentinel token --role analyst` and connect using that token. `SENTINEL_ANALYST_TOKEN` can supply an explicit distinct analyst credential. Administrator-only controls remain enforced server-side.

**Upgrading an existing local copy:** stop its server, back up `.sentinel-data`, and copy the updated source/frontend assets into the existing project without replacing that data directory or your policy customizations. The ZIP excludes runtime credentials and local databases. Reinstall the Python package in your existing Python 3.12+ environment, then restart. Existing AgentGuard data remains in its record namespace; AccountWatch seeds only when requested. Use a fresh disposable `--data-dir` for an isolated demonstration.

The server binds to loopback by default. Keep the synthetic demonstration local. This MVP has no organizational SSO, TLS termination or complete host sandbox. Configurable paths and controls:

```bash
.venv/bin/python -m sentinel serve --host 127.0.0.1 --port 8000 --data-dir .sentinel-data --policy policies/default.json
```

`SENTINEL_DATA_DIR` changes the default state directory. `SENTINEL_ADMIN_TOKEN` supplies an explicit authority credential of at least 24 characters. `SENTINEL_WEBHOOK_URL` or `--webhook-url` enables the loopback security-webhook adapter. Choose `siem`, `slack` or `teams` payload formatting with `SENTINEL_WEBHOOK_ADAPTER` or `--webhook-adapter`; an explicit flag takes precedence. Default alert delivery is a persisted local simulation. All configured webhook URLs must remain loopback HTTP receivers; no live corporate integration is required or claimed. Do not place real secrets in committed files or shell command arguments.

## Demonstrate AgentGuard and the enterprise workflow

After connecting the dashboard, run individual scenarios or the complete sequence:

| Scenario | Action | Observable result |
| --- | --- | --- |
| A — prompt injection | Untrusted repository context attempts an instruction override | Action denied; the same session completes a clean authorized read. |
| B — credential exfiltration | Synthetic API key sent toward an unapproved URL | Outbound action blocked, mock sink unchanged, session quarantined, redacted incident and alert recorded. |
| C — permission misconfiguration | Synthetic agent has wildcard / unsupported permissions | Least-privilege proposal awaits human approval. Approve, apply and inspect validation; rollback is available. |
| D — compromised delegation | Scoped child requests an unauthorized command | Child denied and quarantined; authorized parent work succeeds. |
| E — independent account authorization | Normal, flagged and simulated missed-detection ticket lookups | Authorized ticket succeeds; the out-of-scope ticket remains denied regardless of detector label. |

The CLI runs the same engine in a temporary isolated directory by default:

```bash
.venv/bin/python -m sentinel demo --output work/demo.json
.venv/bin/python -m sentinel demo --scenario b
```

The CLI explicitly simulates the local human authority for scenario C to demonstrate approval, validation and rollback. It finishes with a newly approved restricted configuration. The dashboard deliberately leaves C pending for an operator. Neither path modifies production systems or rotates real credentials.

To retain CLI demo state, supply `--data-dir work/demo-state`. Demonstrations create uniquely identified sessions and are repeatable; deleting a database is not required to rerun them.


For the enterprise workflow, connect as administrator, load the synthetic seed, and run normal operations, threat detection, then investigation/recovery. AccountWatch A–D cover unusual time, abnormal sensitive access, new-device/privilege sequence and possible takeover; AccountWatch E runs the identity-to-agent correlation exercise. Dashboard recovery leaves impactful approval to the operator. Command keeps unverified behavioral anomalies separate from confirmed tool-policy violations.

The CLI supports a reproducible complete synthetic run with **explicit sandbox authority approval**:

```bash
.venv/bin/python -m sentinel enterprise-demo --phase all --approve-sandbox-recovery --output work/enterprise-demo.json
```

```bash
.venv/bin/python -m sentinel enterprise-evaluate --output work/enterprise-evaluation.json
```

Do not treat synthetic precision/recall or correlation fixtures as enterprise performance estimates. Read the actual generated denominators and failure outcomes.

## Test and measure

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m sentinel evaluate --output work/evaluation.json
cd frontend
npm run build
```

The evaluation harness reports actual outcomes for 20 labelled fixtures: 12 malicious and 8 benign. Its measurements cover threat detection, conservative false-positive/noncompletion rate, denied side-effect checks, authorized task completion, local latency, simulated alert delivery, one remediation/rollback workflow, event completeness and four delegation scope requests. Read denominators and case results in the generated JSON. These are measurements for a bounded synthetic corpus and this machine, not goals or enterprise benchmarks.

Browser-level verification was unavailable in the supplied environment. Production TypeScript/build checks, served-bundle checks and API tests do not establish visual layout or browser interaction correctness. The source includes the functional dashboard for local browser review.

Security tests target properties such as missing scope, sandbox escapes, sensitive outbound content, credential redaction, delegation escalation, exact expiring approvals, audit tampering and approval-gated remediation. [Evaluation methodology](docs/evaluation.md) explains how to interpret the results.

[Recorded verification results](docs/verification.md) include the actual test count, bounded corpus measurements, sanitized demo trace, and machine-readable test/evaluation evidence.

## Gateway and API

The local API separates organizational authority from agent identity:

| Route | Credential | Purpose |
| --- | --- | --- |
| `GET /api/health` | None | Minimal local service health. |
| `GET /api/state`, `GET /api/audit/verify` | Authority | Dashboard state and integrity verification. |
| `POST /api/sessions` | Authority | Issue a scoped, expiring session token. |
| `POST /api/gateway/execute` | Agent session | Evaluate and, when allowed, execute a supported action. |
| `POST /api/delegations` | Agent session | Create a child with a subset of live parent scope. |
| `POST /api/approvals/{id}/review` | Authority | Approve/reject one eligible request. |
| `POST /api/remediations`, `.../{id}/apply`, `.../{id}/rollback` | Authority | Propose, apply an approved fix, or restore its original configuration. |
| `POST /api/sessions/{id}/restore` | Authority | Reviewed restoration after required validation. |
| `POST /api/incidents/{id}/review` | Authority | Record a review or appeal without bypassing mandatory rules. |
| `POST /api/demo/run/{a\|b\|c\|d\|e\|all}` | Authority | Run inert demonstrations in the current local state. |

Use `Authorization: Bearer <credential>`. Gateway action fields are `tool`, `operation`, optional `resource`, `destination`, `content`, `context`, `context_source` and `approval_id`. Unknown fields are rejected. Token identity comes from authentication, not from prose or an agent ID inside a payload. Responses contain a decision, execution flag, sanitized event, safe alternative and optional adapter result. API validation errors omit submitted secret values.

An ordinary protected action looks like:

```json
{"tool":"files","operation":"read","resource":"readme.txt","context_source":"repository"}
```

The API schema is available at `/api/openapi.json`; route discovery does not grant authorization. The frontend uses same-origin requests and the service does not enable wildcard CORS.

The interactive API reference at `/api/docs` serves its pinned Swagger UI assets locally under the same content security policy. It makes no CDN requests. Include the appropriate `Bearer` credential in the authorization header field when invoking a protected route.

## AccountWatch and Command API

| Route group | Role | Purpose |
| --- | --- | --- |
| `GET /api/auth/role` | Administrator or analyst | Determine the authenticated local role |
| `GET /api/accountwatch/overview`, `/identities`, `/identities/{id}`, `/identities/{id}/baseline`, `/identities/{id}/activity`, `/anomalies`, `/responses` | Administrator or analyst | Minimized identity, baseline, activity and investigation data |
| `POST /api/accountwatch/events` | Administrator or analyst | Ingest allowlisted synthetic security metadata |
| `POST /api/accountwatch/anomalies/{id}/review` | Administrator or analyst | Expected/escalate/request verification/propose containment/close/reopen with a note |
| `POST /api/accountwatch/responses/{id}/approve` | Administrator | Approve/reject and apply a scoped synthetic response |
| `POST /api/accountwatch/sessions/{id}/verify` | Administrator | Explicit time-bounded mock step-up verification |
| `POST /api/accountwatch/seed`, `/retention/purge`, `/demo/{a\|b\|c\|d\|e}` | Administrator | Seed, purge details, or run controlled identity scenarios |
| `GET /api/command`, `/api/incidents/correlated`, `/api/integrations` | Administrator or analyst | Filtered unified investigations, explicit relationships and mock connector mappings |
| `POST /api/incidents/correlated/{id}/review` | Administrator or analyst | Audited unified incident review; no policy bypass |
| `POST /api/enterprise/demo/{normal\|threat\|recovery\|all}`, `/api/enterprise/evaluate` | Administrator | Run local enterprise stages or measured evaluation |
| `GET /api/enterprise/evaluation` | Administrator or analyst | Read a previously generated measurement, if available |

Typed event ingestion rejects arbitrary employee content, credentials, unknown authority fields and ground-truth labels. Agent ownership is bound by an administrator using `owner_identity_id` and `authentication_session_id`; client tool requests cannot substitute them. Ticket access uses a separately bound `account_scope`. The analyst role cannot access `/api/state` or AgentGuard's administrative controls.

## MCP and IDE guidance

The sample stdio integration exposes `sentinel_execute` and `sentinel_delegate`:

```bash
.venv/bin/python -m sentinel.mcp_server
```

Set `SENTINEL_URL` to the local service URL and provide an issued short-lived `SENTINEL_AGENT_TOKEN` through your runtime's secure environment mechanism. The MCP process never needs the authority token. Start the HTTP service first. This is a minimal local integration sample, not certification against an installed MCP client or Cursor version.

The reusable [agent security skill](integrations/agent-security/SKILL.md) explains protected gateway use and safe redirection. [Cursor guidance](integrations/cursor/README.md) includes an advisory rule example. Apply host-specific integration only after verifying the client's documented mechanism. To constrain a hostile agent across an IDE, remove alternative executable tool paths with a host-level boundary.

## Policies and response

[Policy configuration](docs/policy.md) covers classifications, destination allowlists, protected resources and limits. Hard constraints cannot be approved away. Incoming context remains untrusted, and an agent cannot edit organizational policy through sandbox tools. [Incident response](docs/incident-response.md) describes human approvals, reviews, containment, synthetic fixes, validation, rollback and restoration.

Audit events are hash chained with local integrity material and an integrity anchor. This detects local database alteration under the documented assumptions; someone controlling the gateway process and all integrity files can forge local history. There is no claim of immutable remote evidence. A failed integrity check stops tool execution.

## Deliverables

| Requested deliverable | Implementation |
| --- | --- |
| Threat model | [docs/threat-model.md](docs/threat-model.md) |
| Architecture diagram | [docs/architecture.md](docs/architecture.md) |
| Working backend | `sentinel/api.py`, `sentinel/core.py`, SQLAlchemy store |
| Functional dashboard | `frontend/` React/TypeScript application |
| Policy engine | `Engine` policy evaluation and [policies/default.json](policies/default.json) |
| Four security modules | `sentinel/analyzers.py` |
| Reusable security skill | [integrations/agent-security/SKILL.md](integrations/agent-security/SKILL.md) |
| Protected tool gateway | `POST /api/gateway/execute` and fixed sandbox adapters |
| MCP integration | `sentinel/mcp_server.py` |
| Synthetic simulations | `sentinel/demo.py`, dashboard scenarios A–D |
| Automated security tests | `tests/` and the evaluation harness |
| Incident response workflow | Dashboard + [docs/incident-response.md](docs/incident-response.md) |
| Safe remediation demo | Scenario C, reviewed apply/validation/rollback APIs |
| Setup and execution | This README |
| Hackathon presentation | [docs/hackathon-script.md](docs/hackathon-script.md) |

Production identity, arbitrary host-tool interception, real command execution, real external outbound delivery, production remediation, comprehensive semantic injection detection, encrypted organizational storage, distributed availability and live corporate notification integrations are outside this MVP.

`make verify` builds the dashboard, runs tests and writes local demonstration/evaluation reports under `work/`. `uv.lock` and `frontend/package-lock.json` support dependency reproduction; use `uv sync --locked --extra dev` for the locked Python environment. Installed production dashboard assets live in `frontend/dist` in this source checkout; a backend-only wheel does not bundle the React dashboard.

# Enterprise enhancement audit and implementation plan

## Existing application audit

The existing source is a Python 3.12 FastAPI/Pydantic backend, SQLAlchemy SQLite store with a local keyed audit chain, and React 19/TypeScript/Vite frontend. Four deterministic analyzer modules implement threat detection, identity/access, data privacy, and incident response. The independent fixed-adapter gateway, scoped agent tokens and ancestry checks, exact expiring approvals, synthetic least-privilege repairs, rollback, and separately reviewed restoration are working features to preserve. Existing navigation: Overview, Activity stream, Protected agents, Human approvals, Incident log, Policy & integrations. Typography: locally bundled DM Sans and IBM Plex Mono. Existing UI uses dark surfaces and reusable metric cards, tables, evidence drawers, and human confirmation dialogs. Existing backend routes and action schemas remain compatible.

The conversation defines the absent fifth feature: a normal/flagged/missed detector support-ticket comparison, where an Acme-scoped authenticated agent cannot retrieve a Northstar ticket even if a simulated detector misses the injection. Implement it as actual resource-level authorization in the gateway, not a frontend decision. Display simulated detector evidence separately from mandatory authorization.

The video and linked AccountWatch activity lab are visual references only. Inspect them before applying the palette. The requested delivery is an incremental local full-stack prototype with mock connectors, not a replacement of the reference Site or a claim of Cisco integration.

## Implementation sequence

1. Preserve baseline source and run all existing tests. Record API and data model contracts.
2. Add typed, metadata-only synthetic identity/activity/baseline/anomaly schemas and configurable AccountWatch risk/retention policy. Baselines use a separate normal-history training split; evaluation attacks never update them automatically.
3. Build AccountWatch with robust median/MAD and deterministic contextual/sequence rules. Record own-history and role context; keep anomalies distinct from confirmed violations. Review, step-up proposals, scoped approved containment, close/reopen, notes and retention remain audited.
4. Add immutable server-side identity/auth-session/agent ownership bindings. Require additional human verification for sensitive agent actions under corroborated identity risk; it must never grant capabilities, weaken hard denials, or disable unrelated accounts. Correlation uses explicit identity/session bindings, not time proximity alone.
5. Complete ticket-scope fifth feature and preserve original A–D simulations.
6. Add Command and AccountWatch sections while preserving existing screens. Apply accessible Cisco-oriented dark/cyan semantic colors with original SENTINEL branding; no Cisco logo or endorsement.
7. Add mock Duo/XDR/Secure Access/Identity Intelligence/Splunk adapter previews; no live credentials or external actions. Implement synthetic enterprise seed and full normal→threat→reviewed recovery demonstration.
8. Run regression and adversarial/API tests, measured held-out evaluation, production frontend build and available browser QA. Record verification limits truthfully. Deliver an updated ZIP through the already-authorized connected Drive delivery route, preserving existing customer data directories when upgraded locally.

## New service boundaries

AccountWatch is a separate analytics service sharing the existing integrity-checked Store and lock. AgentGuard remains the execution authority. A correlation service projects explicit ownership and session edges into unified investigations. A role-protected API exposes analytics and review operations. The existing local authority is administrator; an optional distinct analyst credential can read and investigate, but cannot provision agents, approve privileged repairs, edit policies, or authorize containment. A statistical anomaly alone never automatically disables a human account.

## Privacy and failure constraints

Only allowlisted event metadata is accepted; no message bodies, passwords, keystrokes, or surveillance data. IDs are pseudonymous synthetic labels. Policies configure risk thresholds, minimum baseline samples, correlation window, retention, and explicit scoped-response controls. High scores are ordinal visual priorities, not probabilities. Retained raw telemetry must be purged according to its policy without copying all metadata into the immutable audit chain; retain only minimized lifecycle evidence. The audit key and process remain local trusted components; one process/worker is supported. Existing before-execution commit and uncertain-completion semantics remain unchanged.

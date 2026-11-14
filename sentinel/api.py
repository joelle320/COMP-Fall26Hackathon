"""Authenticated local control plane and independent protected-tool entry point."""
import hmac
import os
from pathlib import Path
import secrets
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import SQLAlchemyError
from starlette.types import ASGIApp, Receive, Scope, Send

from .core import Engine


class BoundedRequests:
    """Bound request memory before JSON parsing; do not trust Content-Length."""

    def __init__(self, app: ASGIApp, limit: int = 131_072):
        self.app, self.limit = app, limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.limit:
                return await JSONResponse({"detail": "Request exceeds the 128 KiB gateway limit."}, 413)(scope, receive, send)
            if not message.get("more_body", False):
                break
        received = False

        async def bounded_receive():
            nonlocal received
            if not received:
                received = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, bounded_receive, send)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_max_length=65_536)


class Action(StrictModel):
    tool: str = Field(min_length=1, max_length=48)
    operation: str = Field(min_length=1, max_length=48)
    resource: str | None = Field(default=None, max_length=1024)
    destination: str | None = Field(default=None, max_length=2048)
    content: str | None = Field(default=None, max_length=65_536)
    context: str | None = Field(default=None, max_length=32_768)
    context_source: Literal["repository", "tool", "web", "user"] = "user"
    approval_id: str | None = Field(default=None, max_length=128)


class NewSession(StrictModel):
    agent_id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    role: str = Field(default="developer", max_length=48)
    capabilities: list[str] | None = Field(default=None, max_length=16)
    ttl_seconds: int = Field(default=3600, ge=1, le=86_400)
    owner_identity_id: str | None = Field(default=None, max_length=100)
    authentication_session_id: str | None = Field(default=None, max_length=100)
    account_scope: Literal["Acme", "Northstar"] | None = None


class Delegation(StrictModel):
    agent_id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    capabilities: list[str] = Field(max_length=16)


class Review(StrictModel):
    approved: bool
    reviewer: str | None = Field(default=None, max_length=100)
    note: str = Field(default="", max_length=2000)


class AuthorityAction(StrictModel):
    reviewer: str | None = Field(default=None, max_length=100)
    note: str = Field(default="", max_length=2000)


class Proposal(StrictModel):
    session_id: str = Field(min_length=1, max_length=128)


class InvestigationReview(StrictModel):
    action: Literal["expected", "escalate", "request_verification", "close", "reopen", "propose_containment"]
    note: str = Field(min_length=3, max_length=2000)


class ScopedResponseReview(StrictModel):
    approved: bool
    note: str = Field(min_length=3, max_length=2000)


def load_authority_token(data_dir: Path) -> str:
    """Persist an unguessable local demo authority credential, never in the SPA."""
    configured = os.getenv("SENTINEL_ADMIN_TOKEN")
    if configured:
        if len(configured) < 24:
            raise ValueError("SENTINEL_ADMIN_TOKEN must contain at least 24 characters.")
        return configured
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    token_path = data_dir / "admin.token"
    if token_path.is_symlink():
        raise ValueError("Authority token path must not be a symlink.")
    if token_path.exists():
        os.chmod(token_path, 0o600)
        return token_path.read_text().strip()
    token = secrets.token_urlsafe(48)
    descriptor = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(token + "\n")
    return token


def load_analyst_token(data_dir: Path, create: bool = False) -> str | None:
    configured = os.getenv("SENTINEL_ANALYST_TOKEN")
    if configured:
        if len(configured) < 24:
            raise ValueError("SENTINEL_ANALYST_TOKEN must contain at least 24 characters")
        return configured
    path = data_dir / "analyst.token"
    if path.is_symlink():
        raise ValueError("Analyst credential path must not be a symlink")
    if path.exists():
        os.chmod(path, 0o600)
        return path.read_text().strip()
    if not create:
        return None
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    token = secrets.token_urlsafe(48)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(token + "\n")
    return token


def create_app(data_dir: Path | str | None = None, admin_token: str | None = None,
               testing: bool = False, policy_path: Path | str | None = None,
               webhook_url: str | None = None, webhook_adapter: str | None = None,
               analyst_token: str | None = None) -> FastAPI:
    directory = Path(data_dir or os.getenv("SENTINEL_DATA_DIR", ".sentinel-data")).resolve()
    authority = admin_token or load_authority_token(directory)
    analyst_credential = analyst_token or load_analyst_token(directory, create=not testing)
    if analyst_credential and hmac.compare_digest(analyst_credential.encode(), authority.encode()):
        raise ValueError("Analyst and administrator credentials must be distinct")
    engine = Engine(directory, policy_path=Path(policy_path) if policy_path else None,
                    webhook_url=webhook_url or os.getenv("SENTINEL_WEBHOOK_URL"),
                    webhook_adapter=webhook_adapter or os.getenv("SENTINEL_WEBHOOK_ADAPTER", "siem"))
    app = FastAPI(title="SENTINEL", version="0.1.0", docs_url=None,
                  openapi_url="/api/openapi.json", redoc_url=None)
    app.state.engine = engine
    app.state.testing = testing
    app.add_middleware(BoundedRequests)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        # Bearer-only authorization; no cookies, implicit browser auth, or wildcard CORS.
        origin = request.headers.get("origin")
        if (request.method not in {"GET", "HEAD", "OPTIONS"} and origin
                and origin.rstrip("/") != str(request.base_url).rstrip("/")):
            return JSONResponse({"detail": "Cross-origin control-plane requests are disabled."}, status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request, exc):
        # Pydantic's default `input` can contain a credential. Never reflect it.
        errors = [{"location": list(error["loc"]), "type": error["type"]} for error in exc.errors()]
        return JSONResponse({"detail": "Invalid request fields.", "errors": errors}, status_code=422)

    @app.exception_handler(PermissionError)
    async def permission_denied(_request, _exc):
        return JSONResponse({"detail": "Operation denied by authentication, scope, or policy."}, status_code=403)

    @app.exception_handler(ValueError)
    async def invalid_operation(_request, _exc):
        return JSONResponse({"detail": "Operation is invalid or its required workflow stage is incomplete."}, status_code=400)

    @app.exception_handler(SQLAlchemyError)
    @app.exception_handler(OSError)
    @app.exception_handler(RuntimeError)
    async def unavailable(_request, _exc):
        return JSONResponse({"detail": "Security enforcement unavailable. Tool execution is paused; inspect local system health."}, status_code=503)

    def bearer(authorization: Annotated[str | None, Header()] = None) -> str:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Bearer credential required.")
        token = authorization[7:]
        if not token or len(token) > 512:
            raise HTTPException(401, "Invalid bearer credential.")
        return token

    def admin(token: Annotated[str, Depends(bearer)]) -> str:
        if not hmac.compare_digest(token.encode("utf-8"), authority.encode("utf-8")):
            raise HTTPException(403, "Organizational authority credential required.")
        # A single local authority identity; arbitrary reviewer labels never grant rights.
        return "local-authority"

    def agent(token: Annotated[str, Depends(bearer)]) -> str:
        engine.authenticate(token)
        return token

    def analyst(token: Annotated[str, Depends(bearer)]) -> str:
        if hmac.compare_digest(token.encode(), authority.encode()):
            return "local-authority"
        if analyst_credential and hmac.compare_digest(token.encode(), analyst_credential.encode()):
            return "local-analyst"
        raise HTTPException(403, "An administrator or analyst credential is required.")

    @app.get("/api/auth/role")
    def authenticated_role(reviewer: Annotated[str, Depends(analyst)]):
        return {"role": "admin" if reviewer == "local-authority" else "analyst", "tenant_id": "sentinel-demo"}

    @app.get("/api/accountwatch/overview")
    def aw_overview(_reviewer: Annotated[str, Depends(analyst)]):
        return engine.accountwatch.overview()

    @app.get("/api/accountwatch/identities")
    def aw_identities(_reviewer: Annotated[str, Depends(analyst)]):
        return engine.accountwatch.identities()

    @app.get("/api/accountwatch/identities/{identity_id}")
    def aw_identity(identity_id: str, _reviewer: Annotated[str, Depends(analyst)]):
        return engine.accountwatch.detail(identity_id)

    @app.get("/api/accountwatch/identities/{identity_id}/baseline")
    def aw_baseline(identity_id: str, _reviewer: Annotated[str, Depends(analyst)]):
        return engine.accountwatch.baseline(identity_id)

    @app.get("/api/accountwatch/identities/{identity_id}/activity")
    def aw_activity(identity_id: str, _reviewer: Annotated[str, Depends(analyst)]):
        return engine.accountwatch.activity(identity_id)

    @app.get("/api/accountwatch/anomalies")
    def aw_anomalies(_reviewer: Annotated[str, Depends(analyst)]):
        return engine.accountwatch.anomalies()

    @app.get("/api/accountwatch/responses")
    def aw_responses(_reviewer: Annotated[str, Depends(analyst)]):
        return engine.accountwatch.responses()

    @app.post("/api/accountwatch/seed")
    def aw_seed(_reviewer: Annotated[str, Depends(admin)]):
        return engine.accountwatch.seed()

    # Activity ingestion has a dedicated allowlisted typed schema. Imported here
    # after service initialization; unknown content or authority fields are rejected.
    from .accountwatch_models import ActivityEvent as ActivityEventInput

    @app.post("/api/accountwatch/events", status_code=201)
    def aw_ingest(body: ActivityEventInput, _reviewer: Annotated[str, Depends(analyst)]):
        return engine.accountwatch.ingest(body.model_dump(mode="json", exclude_none=True))

    @app.post("/api/accountwatch/anomalies/{anomaly_id}/review")
    def aw_review(anomaly_id: str, body: InvestigationReview, reviewer: Annotated[str, Depends(analyst)]):
        return engine.accountwatch.review(anomaly_id, body.action, body.note, reviewer)

    @app.post("/api/accountwatch/responses/{response_id}/approve")
    def aw_response(response_id: str, body: ScopedResponseReview, reviewer: Annotated[str, Depends(admin)]):
        return engine.accountwatch.approve_response(response_id, body.approved, reviewer, body.note)

    @app.post("/api/accountwatch/sessions/{session_id}/verify")
    def aw_verify(session_id: str, body: AuthorityAction, reviewer: Annotated[str, Depends(admin)]):
        if len(body.note.strip()) < 3:
            raise HTTPException(400, "A verification review note is required.")
        binding = engine.store.get("aw_auth_session", session_id)
        if not binding:
            raise HTTPException(404, "Unknown synthetic authentication session.")
        return engine.accountwatch.verify_session(binding["identity_id"], session_id, reviewer, body.note)

    @app.post("/api/accountwatch/retention/purge")
    def aw_purge(_reviewer: Annotated[str, Depends(admin)]):
        return engine.accountwatch.purge_expired()

    @app.post("/api/accountwatch/demo/{scenario}")
    def aw_demo(scenario: Literal["a", "b", "c", "d", "e"], _reviewer: Annotated[str, Depends(admin)]):
        if scenario == "e":
            return engine.enterprise.demo("threat")
        return engine.accountwatch.demo(scenario)

    @app.get("/api/incidents/correlated")
    def correlated(_reviewer: Annotated[str, Depends(analyst)]):
        return engine.enterprise.correlated()

    @app.post("/api/incidents/correlated/{incident_id}/review")
    def correlated_review(incident_id: str, body: InvestigationReview, reviewer: Annotated[str, Depends(analyst)]):
        return engine.enterprise.review(incident_id, body.action, body.note, reviewer)

    @app.get("/api/command")
    def command(_reviewer: Annotated[str, Depends(analyst)], module: str | None = None,
                risk_level: str | None = None, identity_id: str | None = None, agent_id: str | None = None,
                incident_type: str | None = None, time_range: str | None = None, status: str | None = None,
                search: str | None = None):
        filters = {k: v for k, v in {"module": module, "risk_level": risk_level, "identity_id": identity_id,
                   "agent_id": agent_id, "incident_type": incident_type, "time_range": time_range, "status": status, "search": search}.items() if v}
        if any(len(str(value)) > 200 for value in filters.values()):
            raise HTTPException(400, "Filter value exceeds its bounded length.")
        return engine.enterprise.command(filters)

    @app.get("/api/integrations")
    def integrations(_reviewer: Annotated[str, Depends(analyst)]):
        return engine.enterprise.connectors()

    @app.post("/api/enterprise/demo/{phase}")
    def enterprise_demo(phase: Literal["normal", "threat", "recovery", "all"], _reviewer: Annotated[str, Depends(admin)]):
        return engine.enterprise.demo(phase)

    @app.post("/api/enterprise/evaluate")
    def enterprise_evaluate(_reviewer: Annotated[str, Depends(admin)]):
        from .combined_evaluation import evaluate_enterprise_suite
        result = evaluate_enterprise_suite()
        engine.store.save("enterprise_evaluation", "latest", result)
        return result

    @app.get("/api/enterprise/evaluation")
    def enterprise_evaluation(_reviewer: Annotated[str, Depends(analyst)]):
        return engine.store.get("enterprise_evaluation", "latest") or {"available": False, "note": "Run the local evaluation to obtain measured results."}

    @app.get("/api/health")
    def health():
        audit = engine.verify_audit()
        return {"status": "healthy" if audit.get("valid") else "degraded",
                "audit_valid": audit.get("valid", False), "mode": "local-sandbox",
                "version": "0.1.0"}

    documentation_assets = Path(__file__).resolve().parent / "static"
    app.mount("/api/documentation-assets", StaticFiles(directory=documentation_assets), name="documentation-assets")

    @app.get("/api/docs", include_in_schema=False)
    def api_docs():
        return HTMLResponse('''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>SENTINEL API</title>
<link rel="stylesheet" href="/api/documentation-assets/swagger-ui.css"></head><body>
<div id="swagger-ui"></div><script src="/api/documentation-assets/swagger-ui-bundle.js"></script>
<script src="/api/documentation-assets/swagger-init.js"></script></body></html>''')

    @app.get("/api/state")
    def state(_authority: Annotated[str, Depends(admin)]):
        return engine.snapshot()

    @app.get("/api/audit/verify")
    def audit(_authority: Annotated[str, Depends(admin)]):
        return engine.verify_audit()

    @app.post("/api/sessions", status_code=201)
    def sessions(body: NewSession, _authority: Annotated[str, Depends(admin)]):
        return engine.create_session(**body.model_dump(exclude_none=True))

    @app.post("/api/delegations", status_code=201)
    def delegations(body: Delegation, token: Annotated[str, Depends(agent)]):
        return engine.delegate(token, body.agent_id, body.capabilities)

    @app.post("/api/gateway/execute")
    def gateway(body: Action, token: Annotated[str, Depends(agent)]):
        return engine.execute(token, body.model_dump(exclude_none=True))

    @app.post("/api/approvals/{approval_id}/review")
    def review(approval_id: str, body: Review, reviewer: Annotated[str, Depends(admin)]):
        return engine.review_approval(approval_id, body.approved, reviewer)

    @app.post("/api/remediations", status_code=201)
    def propose(body: Proposal, _authority: Annotated[str, Depends(admin)]):
        return engine.propose_remediation(body.session_id)

    @app.post("/api/remediations/{remediation_id}/apply")
    def apply(remediation_id: str, body: AuthorityAction, reviewer: Annotated[str, Depends(admin)]):
        return engine.apply_remediation(remediation_id, reviewer)

    @app.post("/api/remediations/{remediation_id}/rollback")
    def rollback(remediation_id: str, body: AuthorityAction, reviewer: Annotated[str, Depends(admin)]):
        return engine.rollback_remediation(remediation_id, reviewer)

    @app.post("/api/sessions/{session_id}/restore")
    def restore(session_id: str, body: AuthorityAction, reviewer: Annotated[str, Depends(admin)]):
        if not body.note.strip():
            raise HTTPException(400, "A human review note is required before restoration.")
        return engine.restore_session(session_id, reviewer, body.note)

    @app.post("/api/incidents/{event_id}/review")
    def incident_review(event_id: str, body: AuthorityAction, reviewer: Annotated[str, Depends(admin)]):
        if not body.note.strip():
            raise HTTPException(400, "An incident review note is required.")
        return engine.review_incident(event_id, reviewer, body.note)

    @app.post("/api/demo/run/{scenario}")
    def run_demo(scenario: Literal["a", "b", "c", "d", "e", "all"], _authority: Annotated[str, Depends(admin)]):
        if scenario == "e":
            from .tickets import run_ticket_demo
            return run_ticket_demo(engine)
        from .demo import run_scenario
        return run_scenario(engine, scenario, complete_remediation=False)

    frontend = Path(__file__).resolve().parent.parent / "frontend" / "dist"
    if (frontend / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=frontend / "assets"), name="assets")

    @app.get("/", include_in_schema=False)
    def dashboard():
        if (frontend / "index.html").exists():
            return FileResponse(frontend / "index.html")
        return JSONResponse({"message": "SENTINEL backend ready. Build the dashboard: cd frontend && npm ci && npm run build",
                             "api_docs": "/api/docs", "health": "/api/health"})

    @app.get("/sentinel.svg", include_in_schema=False)
    def favicon():
        if (frontend / "sentinel.svg").is_file():
            return FileResponse(frontend / "sentinel.svg", media_type="image/svg+xml")
        raise HTTPException(404, "Dashboard asset unavailable; build the frontend first.")

    return app

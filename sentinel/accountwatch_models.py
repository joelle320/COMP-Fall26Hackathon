"""Metadata-only AccountWatch schemas. No free-form employee content is accepted."""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

Identifier = str

class MetadataModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_max_length=120, allow_inf_nan=False)

class ActivityEvent(MetadataModel):
    id: str | None = Field(default=None, min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.:-]+$")
    identity_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.:-]+$")
    authentication_session_id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    timestamp: AwareDatetime
    category: Literal["auth_success", "auth_failure", "file_access", "privilege_change", "data_transfer", "admin_action", "session_end"]
    application: str = Field(default="SupportDesk", min_length=1, max_length=60, pattern=r"^[A-Za-z0-9_. -]+$")
    resource_category: Literal["public", "internal", "confidential", "credentials"] = "internal"
    device_id: str = Field(default="synthetic-device", min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.:-]+$")
    device_familiar: bool | None = None
    region: str = Field(default="US-East", min_length=1, max_length=40, pattern=r"^[A-Za-z0-9 -]+$")
    file_count: int = Field(default=0, ge=0, le=1_000_000, strict=True)
    sensitive_file_count: int = Field(default=0, ge=0, le=1_000_000, strict=True)
    data_mb: float = Field(default=0, ge=0, le=1_000_000)
    failed_attempts: int = Field(default=0, ge=0, le=10000, strict=True)
    duration_minutes: float = Field(default=0, ge=0, le=10080)
    privilege: Literal["none", "admin"] = "none"
    destination: str | None = Field(default=None, max_length=200)
    authorized_role: bool = True
    approved_after_hours: bool = False
    approved_travel: bool = False
    mfa_verified: bool = False

class EmployeeIdentity(MetadataModel):
    id: str
    name: str
    kind: Literal["employee", "service"] = "employee"
    tenant_id: str = "sentinel-demo"
    role: str
    timezone: str = "America/New_York"
    status: str = "active"
    created_at: datetime
    authorized_resource_categories: list[str] = Field(default_factory=lambda: ["public", "internal"])

class ServiceIdentity(EmployeeIdentity):
    kind: Literal["service"] = "service"

class AuthenticationSession(MetadataModel):
    id: str
    identity_id: str
    tenant_id: str = "sentinel-demo"
    status: str
    created_at: AwareDatetime
    expires_at: AwareDatetime
    device_id: str
    verified_until: AwareDatetime | None = None

class AnomalyReview(MetadataModel):
    action: Literal["expected", "escalate", "request_verification", "close", "reopen", "propose_containment"]
    note: str = Field(min_length=3, max_length=2000)


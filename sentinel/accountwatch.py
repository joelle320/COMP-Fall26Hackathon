"""Explainable, metadata-only UEBA for synthetic identities.

Baselines are fitted only by trusted seeding from normal-history fixtures. Ingested
observations never retrain them. Scores prioritize review; they are not calibrated
probabilities or a finding of employee intent.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import math
import statistics
import time
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4
from zoneinfo import ZoneInfo

from .accountwatch_models import ActivityEvent, EmployeeIdentity
from .analyzers import redact

DEFAULT_POLICY = {
    "thresholds": [
        {"label": "informational", "min": 0, "max": 24},
        {"label": "low", "min": 25, "max": 49},
        {"label": "moderate", "min": 50, "max": 69},
        {"label": "high", "min": 70, "max": 89},
        {"label": "critical", "min": 90, "max": 100},
    ],
    "retention_days": 30, "baseline_retention_days": 90, "min_samples": 10,
    "correlation_window_minutes": 30, "step_up_score": 70,
    "review_score": 50, "verification_minutes": 15,
    "auth_frequency_ceiling": 5, "privileged_roles": ["security", "operations"],
    "destination_allowlist": ["https://api.internal.example", "https://siem.internal.example"],
    "purpose": "Synthetic security anomaly investigation; never productivity or disciplinary monitoring",
    "tenant_id": "sentinel-demo", "automatic_account_disable": False,
}


def utcnow():
    return datetime.now(timezone.utc)


def stamp():
    return utcnow().isoformat()


def uid():
    return str(uuid4())


def parsed(value):
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def median_mad(values):
    median = statistics.median(values) if values else 0
    mad = statistics.median(abs(value - median) for value in values) if values else 0
    spread = max(1.4826 * mad, max(1, median * .10))
    return {"median": round(median, 3), "mad": round(mad, 3), "lower": round(max(0, median - 3 * spread), 3),
            "upper": round(median + 3 * spread, 3)}


class AccountWatch:
    def __init__(self, store, policy: dict | None = None):
        self.store, self.lock = store, store.lock
        self.policy = {**DEFAULT_POLICY, **(policy or {})}
        thresholds = self.policy["thresholds"]
        if not isinstance(thresholds, list) or len(thresholds) != 5:
            raise ValueError("Five ordered risk thresholds are required")
        expected = 0
        for threshold in thresholds:
            if set(threshold) != {"label", "min", "max"} or threshold["min"] != expected or threshold["max"] < expected:
                raise ValueError("Risk threshold bands must be contiguous from zero to one hundred")
            if threshold["label"] not in {"informational", "low", "moderate", "high", "critical"}:
                raise ValueError("Unknown risk label")
            expected = threshold["max"] + 1
        if expected != 101 or len({item["label"] for item in thresholds}) != 5:
            raise ValueError("Risk threshold bands must cover zero to one hundred")
        for key, limit in (("retention_days", 365), ("baseline_retention_days", 365), ("min_samples", 1000),
                           ("correlation_window_minutes", 1440), ("verification_minutes", 60)):
            value = self.policy[key]
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= limit:
                raise ValueError("Invalid bounded analytics policy")
        for key in ("step_up_score", "review_score"):
            if not isinstance(self.policy[key], int) or not 1 <= self.policy[key] <= 100:
                raise ValueError("Invalid review threshold")
        if self.policy["tenant_id"] != "sentinel-demo":
            raise ValueError("This prototype supports one explicit synthetic tenant")
        if not isinstance(self.policy["auth_frequency_ceiling"], int) or not 2 <= self.policy["auth_frequency_ceiling"] <= 100:
            raise ValueError("Invalid authentication-frequency ceiling")
        if not isinstance(self.policy["privileged_roles"], list) or any(not isinstance(role, str) for role in self.policy["privileged_roles"]):
            raise ValueError("Privileged roles must be an explicit policy list")

    def _check(self):
        if not self.store.verify()["valid"]:
            raise RuntimeError("AccountWatch audit integrity unavailable")

    def _get_identity(self, identity_id):
        identity = self.store.get("aw_identity", identity_id)
        if not identity or identity.get("tenant_id") != self.policy["tenant_id"]:
            raise ValueError("Unknown scoped synthetic identity")
        return identity

    def _level(self, score):
        return next(item["label"] for item in self.policy["thresholds"] if item["min"] <= score <= item["max"])

    def seed(self):
        from .synthetic import generate_dataset
        with self.lock:
            self._check()
            existing = self.store.list("aw_identity")
            if len(existing) == 23 and len([item for item in self.store.list("aw_baseline") if item.get("status") != "expired"]) == 23:
                return {"seeded": False, "identities": len(existing), "employee_count": sum(i["kind"] == "employee" for i in existing),
                        "service_count": sum(i["kind"] == "service" for i in existing), "training_samples": sum(b["sample_count"] for b in self.store.list("aw_baseline"))}
            dataset = generate_dataset()
            training = dataset["training"]
            for supplied in dataset["identities"]:
                prior = self.store.get("aw_baseline", supplied["id"])
                if self.store.get("aw_identity", supplied["id"]) and prior and prior.get("status") != "expired":
                    continue
                identity = {**supplied, "created_at": supplied.get("created_at", stamp()), "status": "active"}
                identity = EmployeeIdentity.model_validate(identity).model_dump(mode="json")
                self.store.save("aw_identity", identity["id"], identity)
                rows = [row for row in training if row["identity_id"] == identity["id"]]
                role_ids = {item["id"] for item in dataset["identities"] if item["role"] == identity["role"]}
                role_rows = [row for row in training if row["identity_id"] in role_ids]
                auth_rows = [row for row in rows if row["category"] == "auth_success"]
                hours = [parsed(row["timestamp"]).astimezone(ZoneInfo(identity["timezone"])).hour for row in auth_rows]
                auth_days = {}
                for row in auth_rows:
                    day = parsed(row["timestamp"]).astimezone(ZoneInfo(identity["timezone"])).date().isoformat()
                    auth_days[day] = auth_days.get(day, 0) + 1
                auth_frequency = median_mad(list(auth_days.values()))
                resources = {}
                for row in rows:
                    resource = row.get("resource_category", "internal")
                    resources[resource] = resources.get(resource, 0) + 1
                baseline = {
                    "id": f"baseline-{identity['id']}", "identity_id": identity["id"], "tenant_id": identity["tenant_id"],
                    "created_at": stamp(), "sample_count": len(rows), "training_split": "normal-history",
                    "fit_method": "median and median absolute deviation; trusted normal training split only",
                    "training_start": min(row["timestamp"] for row in rows), "training_end": max(row["timestamp"] for row in rows),
                    "file_count": median_mad([row.get("file_count", 0) for row in rows]),
                    "sensitive_file_count": median_mad([row.get("sensitive_file_count", 0) for row in rows]),
                    "failed_attempts": median_mad([row.get("failed_attempts", 0) for row in rows]),
                    "duration_minutes": median_mad([row.get("duration_minutes", 0) for row in rows]),
                    "data_mb": median_mad([row.get("data_mb", 0) for row in rows]),
                    "login_hours": [hours.count(hour) for hour in range(24)],
                    "typical_auth_hours": list(range(24)) if identity["kind"] == "service" else sorted({candidate for hour in hours for candidate in (hour - 1, hour, hour + 1) if 0 <= candidate <= 23}),
                    "login_frequency": {"sampled_authentications": len(auth_rows), "training_days": 30,
                                        "observed_day_counts": auth_days, "observed_daily_count": auth_frequency,
                                        "upper_per_30_minutes": max(self.policy["auth_frequency_ceiling"], math.ceil(auth_frequency["upper"])),
                                        "method": "robust count range on days with normal sampled authentication observations, with a conservative policy floor for the rolling 30-minute review window; not an estimate of complete daily login totals"},
                    "familiar_devices": sorted({row["device_id"] for row in rows}), "regions": sorted({row["region"] for row in rows}),
                    "applications": sorted({row["application"] for row in rows}), "resource_frequency": resources,
                    "role_baseline": {"role": identity["role"], "sample_count": len(role_rows), "file_count": median_mad([row.get("file_count", 0) for row in role_rows])},
                    "training_series": [{"timestamp": row["timestamp"], "file_count": row.get("file_count", 0),
                                         "login_hour": parsed(row["timestamp"]).astimezone(ZoneInfo(identity["timezone"])).hour,
                                         "failed_attempts": row.get("failed_attempts", 0)} for row in rows],
                }
                self.store.save("aw_baseline", identity["id"], baseline)
            return {"seeded": True, "identities": len(dataset["identities"]), "employee_count": 20,
                    "service_count": len(dataset["identities"]) - 20, "training_samples": len(training), "split": "normal-history only"}

    def baseline(self, identity_id):
        with self.lock:
            self._check()
            self._get_identity(identity_id)
            result = self.store.get("aw_baseline", identity_id)
            if not result or result.get("status") == "expired":
                raise ValueError("No fitted baseline")
            return result

    def activity(self, identity_id):
        with self.lock:
            self._check()
            self._get_identity(identity_id)
            return sorted((event for event in self.store.list("aw_event") if not event.get("purged") and event.get("identity_id") == identity_id),
                          key=lambda event: event["timestamp"], reverse=True)[:500]

    def anomalies(self):
        with self.lock:
            self._check()
            return sorted(self.store.list("aw_anomaly"), key=lambda anomaly: anomaly["timestamp"], reverse=True)

    def identities(self):
        with self.lock:
            self._check()
            anomalies = self.store.list("aw_anomaly")
            result = []
            for identity in self.store.list("aw_identity"):
                active = [item for item in anomalies if item["identity_id"] == identity["id"] and item["status"] not in {"expected", "closed"}]
                score = max((item["risk_score"] for item in active), default=0)
                result.append({**identity, "risk_score": score, "risk_level": self._level(score), "anomaly_count": len(active)})
            return sorted(result, key=lambda identity: identity["id"])

    def detail(self, identity_id):
        with self.lock:
            self._check()
            identity = next((item for item in self.identities() if item["id"] == identity_id), None)
            if identity is None:
                raise ValueError("Unknown scoped identity")
            return {"identity": identity, "baseline": self.baseline(identity_id), "activity": self.activity(identity_id),
                    "anomalies": [item for item in self.anomalies() if item["identity_id"] == identity_id],
                    "auth_sessions": [item for item in self.store.list("aw_auth_session") if item["identity_id"] == identity_id]}

    def overview(self):
        with self.lock:
            self._check()
            identities, anomalies = self.identities(), self.anomalies()
            events = sorted((event for event in self.store.list("aw_event") if not event.get("purged")), key=lambda event: event["timestamp"], reverse=True)[:1000]
            active = [item for item in anomalies if item["status"] not in {"expected", "closed"}]
            return {"counts": {"total_identities": len(identities), "active_accounts": sum(item["status"] == "active" for item in identities),
                               "accounts_with_anomalies": len({item["identity_id"] for item in active}),
                               "pending_reviews": sum(item["risk_score"] >= self.policy["review_score"] for item in active),
                               "resolved_incidents": sum(item["status"] in {"closed", "expected"} for item in anomalies)},
                    "policy": self.policy, "identities": identities, "anomalies": anomalies, "events": events,
                    "baselines": self.store.list("aw_baseline"), "responses": self.responses(), "synthetic": True,
                    "privacy": {"purpose": self.policy["purpose"], "content_collection": False, "risk_is_probability": False}}

    def validate_binding(self, identity_id, authentication_session_id):
        with self.lock:
            self._check()
            identity = self._get_identity(identity_id)
            session = self.store.get("aw_auth_session", authentication_session_id)
            if (identity["status"] != "active" or not session or session["identity_id"] != identity_id or session["tenant_id"] != identity["tenant_id"]
                    or session["status"] not in {"active", "step_up_required"} or parsed(session["expires_at"]) <= utcnow()):
                raise PermissionError("The identity/session ownership binding is not active and authorized")
            return session

    def _session(self, event):
        existing = self.store.get("aw_auth_session", event["authentication_session_id"])
        if existing and existing["identity_id"] != event["identity_id"]:
            raise PermissionError("Authentication session ownership cannot change")
        if existing and parsed(existing["expires_at"]) <= parsed(event["timestamp"]):
            raise PermissionError("Authentication session expired")
        if not existing and event["category"] not in {"auth_success", "auth_failure"}:
            raise ValueError("An authentication event must establish the session before resource activity")
        if existing and existing["status"] in {"pending_auth", "ended"} and event["category"] not in {"auth_success", "auth_failure", "session_end"}:
            raise PermissionError("Resource activity requires an explicitly authenticated live session")
        if existing and existing["status"] == "ended" and event["category"] == "auth_success":
            raise PermissionError("An ended authentication session identifier cannot be reused")
        if not existing:
            existing = {"id": event["authentication_session_id"], "identity_id": event["identity_id"], "tenant_id": self.policy["tenant_id"],
                        "created_at": event["timestamp"], "expires_at": (parsed(event["timestamp"]) + timedelta(hours=8)).isoformat(),
                        "status": "active" if event["category"] == "auth_success" else "pending_auth", "device_id": event["device_id"],
                        "verified_until": None}
        elif event["category"] == "auth_success" and existing["status"] == "pending_auth":
            existing.update(status="active", device_id=event["device_id"])
        if event["category"] == "session_end":
            existing["status"] = "ended"
        return existing

    def ingest(self, supplied: dict):
        started = time.perf_counter()
        event = ActivityEvent.model_validate(supplied).model_dump(mode="json", exclude_none=True)
        if redact(event) != event:
            raise ValueError("Credential- or personal-data-shaped metadata is not accepted")
        timestamp = parsed(event["timestamp"])
        if timestamp > utcnow() + timedelta(minutes=5) or timestamp < utcnow() - timedelta(days=90):
            raise ValueError("Telemetry timestamp is outside the supported bounded observation window")
        with self.lock:
            self._check()
            identity = self._get_identity(event["identity_id"])
            baseline = self.baseline(identity["id"])
            event["id"] = event.get("id") or uid()
            if self.store.get("aw_event", event["id"]):
                raise ValueError("Activity identifiers cannot overwrite existing evidence")
            auth_session = self._session(event)
            recent = [item for item in self.activity(identity["id"]) if item["authentication_session_id"] == event["authentication_session_id"]
                      and timedelta(0) <= timestamp - parsed(item["timestamp"]) <= timedelta(minutes=self.policy["correlation_window_minutes"])]
            reasons = []
            def add(code, explanation, weight, **evidence):
                reasons.append({"code": code, "explanation": explanation, "weight": weight, "evidence": redact(evidence)})
            familiar = event["device_id"] in baseline["familiar_devices"]
            event["device_familiar"] = familiar  # Caller-provided familiarity never overrides fitted evidence.
            local_hour = timestamp.astimezone(ZoneInfo(identity["timezone"])).hour
            if event["category"] == "auth_success" and local_hour not in baseline["typical_auth_hours"]:
                if event["approved_after_hours"] and familiar and event["mfa_verified"]:
                    add("APPROVED_AFTER_HOURS", "Approved after-hours work on a familiar verified device is an expected exception.", 0, local_hour=local_hour)
                else:
                    add("UNUSUAL_LOGIN_HOUR", "Authentication is outside this identity's normal local-hour range; time alone does not indicate compromise.", 10, local_hour=local_hour)
            if not familiar:
                add("UNFAMILIAR_DEVICE", "Device identifier is absent from this account's fitted normal-history baseline.", 25, device_id=event["device_id"])
            if event["region"] not in baseline["regions"]:
                if event["approved_travel"] and event["mfa_verified"]:
                    add("APPROVED_TRAVEL", "Coarse region differs during approved, verified travel; this exception does not imply malicious intent.", 0, region=event["region"])
                else:
                    add("UNUSUAL_COARSE_REGION", "Coarse region differs from the account's own history and lacks an approved travel context.", 20, region=event["region"])
            if event["application"] not in baseline["applications"]:
                add("UNUSUAL_APPLICATION", "Application is not present in this account's normal-history sample.", 5, application=event["application"])
            resource_authorized = event["resource_category"] in identity["authorized_resource_categories"]
            privileged_action = event["category"] in {"privilege_change", "admin_action"}
            role_authorized = identity["role"] in self.policy["privileged_roles"] if privileged_action else resource_authorized
            # Collector context may narrow known scope but cannot grant a role a
            # resource or privilege absent from trusted identity configuration.
            event["authorized_role"] = event["authorized_role"] and role_authorized
            if event["category"] in {"file_access", "data_transfer"} and not resource_authorized:
                add("ROLE_RESOURCE_SCOPE", "The observed resource category is outside this synthetic role's configured scope; verify the authorization context without inferring employee intent.", 40,
                    role=identity["role"], observed_category=event["resource_category"], allowed_categories=identity["authorized_resource_categories"])
            if baseline["sample_count"] < self.policy["min_samples"]:
                add("INSUFFICIENT_BASELINE", "There are insufficient normal observations for statistical volume attribution; review context only.", 0)
            else:
                normal = baseline["file_count"]
                if event["file_count"] > normal["upper"]:
                    role_range = baseline["role_baseline"]["file_count"]
                    weight = 15 if event["authorized_role"] and event["file_count"] <= role_range["upper"] else 35
                    add("PERSONAL_FILE_VOLUME", "File-access volume exceeds the account's robust personal range; role context is supporting evidence, not proof of intent.", weight,
                        observed=event["file_count"], personal_median=normal["median"], personal_upper=normal["upper"], role_median=role_range["median"], role_upper=role_range["upper"])
                if event["sensitive_file_count"] > baseline["sensitive_file_count"]["upper"] + 5:
                    add("SENSITIVE_ACCESS_BURST", "Sensitive-file count exceeds this identity's historical range.", 20,
                        observed=event["sensitive_file_count"], baseline_upper=baseline["sensitive_file_count"]["upper"])
                if event["duration_minutes"] > max(baseline["duration_minutes"]["upper"] * 2, 600):
                    add("UNUSUAL_SESSION_DURATION", "Session duration substantially exceeds this account's fitted normal range.", 10, observed_minutes=event["duration_minutes"])
                if event["data_mb"] > max(baseline["data_mb"]["upper"] * 3, 250):
                    add("DATA_ACCESS_VOLUME", "Observed access volume is substantially above the account's normal metadata range.", 15, observed_mb=event["data_mb"])
            failures = sum(max(1, item["failed_attempts"]) for item in recent if item["category"] == "auth_failure")
            current_failures = event["failed_attempts"] if event["category"] == "auth_failure" else 0
            if current_failures >= 5:
                add("REPEATED_AUTH_FAILURES", "The authentication session reports repeated failed attempts; investigate corroborating evidence.", 25, failed_attempts=current_failures)
            if event["category"] == "auth_success" and failures >= 5:
                add("FAILURES_THEN_SUCCESS", "Repeated failures were followed by successful authentication in the same explicitly identified session.", 30, previous_failures=failures)
            if event["category"] == "auth_success":
                identity_recent = [item for item in self.activity(identity["id"]) if item["category"] == "auth_success"
                                   and timedelta(0) <= timestamp - parsed(item["timestamp"]) <= timedelta(minutes=30)]
                if len(identity_recent) >= baseline["login_frequency"]["upper_per_30_minutes"]:
                    add("AUTHENTICATION_FREQUENCY", "Authentication frequency exceeds the personal observed-day robust count range with a conservative policy floor for this rolling window; this is a contextual indicator rather than employee intent.", 20,
                        observations_in_30_minutes=len(identity_recent) + 1, personal_observed_daily_count=baseline["login_frequency"]["observed_daily_count"],
                        review_window_ceiling=baseline["login_frequency"]["upper_per_30_minutes"])
            successful = any(item["category"] == "auth_success" for item in recent)
            if event["category"] == "file_access" and event["resource_category"] in {"confidential", "credentials"} and failures >= 5 and successful:
                add("POSSIBLE_TAKEOVER_SEQUENCE", "Failures, successful authentication, and sensitive access share an explicit account/session binding within the policy window; this is association, not proof of compromise.", 40,
                    supporting_event_ids=[item["id"] for item in recent if item["category"] in {"auth_failure", "auth_success"}])
            if event["category"] in {"privilege_change", "admin_action"}:
                new_device_login = [item for item in recent if item["category"] == "auth_success" and not item.get("device_familiar", True)]
                if new_device_login:
                    add("NEW_DEVICE_PRIVILEGE_SEQUENCE", "An unfamiliar-device login preceded a privileged action in the same authentication session.", 50, supporting_event_ids=[item["id"] for item in new_device_login])
                if not event["authorized_role"] or event["resource_category"] == "credentials":
                    add("PRIVILEGE_POLICY_VIOLATION", "The privileged operation is outside the supplied authorized-role context; deterministic policy sets a minimum critical priority.", 90, authorized_role=event["authorized_role"])
                administrative = [item for item in recent if item["category"] == "admin_action"]
                if len(administrative) >= 3:
                    add("ADMIN_ACTION_BURST", "Several administrative operations occurred in one short explicitly bound session.", 30, previous_admin_actions=len(administrative))
            if event["category"] == "data_transfer":
                try:
                    destination = urlsplit(event.get("destination", ""))
                    origin = f"{destination.scheme}://{destination.netloc}"
                    allowed = destination.scheme == "https" and not destination.username and not destination.password and origin in self.policy["destination_allowlist"]
                except ValueError:
                    allowed = False
                if not allowed:
                    add("UNAPPROVED_TRANSFER_DESTINATION", "Transfer metadata names a destination outside the exact-origin organizational allowlist.", 70)
                if event["resource_category"] in {"confidential", "credentials"}:
                    add("SENSITIVE_TRANSFER_CONTEXT", "The proposed transfer involves classified resources; review required regardless of a statistical baseline.", 30)
            score = min(100, sum(item["weight"] for item in reasons))
            if any(item["code"] == "PRIVILEGE_POLICY_VIOLATION" for item in reasons):
                score = max(score, 90)
            explanation = " ".join(item["explanation"] for item in reasons) or "Observed metadata is within the personal baseline and known contextual policy."
            risk = {"score": score, "level": self._level(score), "reasons": reasons, "is_probability": False}
            event.update(tenant_id=identity["tenant_id"], received_at=stamp(), risk_score=score, risk_level=risk["level"],
                         reasons=reasons, explanation=explanation, investigation_status="observed", synthetic=True,
                         detection_latency_ms=round((time.perf_counter() - started) * 1000, 3))
            # Remove any credential-like values from accepted bounded metadata.
            event = redact(event)
            if event["identity_id"] != identity["id"] or event["authentication_session_id"] != auth_session["id"]:
                raise ValueError("Credential-shaped identity labels are not accepted")
            self.store.save("aw_auth_session", auth_session["id"], auth_session)
            self.store.save("aw_event", event["id"], event)
            anomaly = None
            if score >= self.policy["thresholds"][1]["min"]:
                anomaly = {"id": uid(), "identity_id": identity["id"], "tenant_id": identity["tenant_id"],
                           "authentication_session_id": auth_session["id"], "event_id": event["id"], "event_ids": [event["id"]],
                           "timestamp": event["timestamp"], "created_at": stamp(), "risk_score": score, "risk_level": risk["level"],
                           "reason_codes": [item["code"] for item in reasons], "reasons": reasons, "explanation": explanation,
                           "classification": "behavioral_anomaly", "module": "accountwatch", "status": "open", "review_history": [],
                           "recommended_responses": ["Review minimized account/session evidence", "Request scoped step-up verification" if score >= self.policy["step_up_score"] else "Check authorized business context"],
                           "automatic_enforcement": False, "compromise_confirmed": False,
                           "detection_latency_ms": event["detection_latency_ms"], "alert_created_at": stamp()}
                self.store.save("aw_anomaly", anomaly["id"], anomaly)
            return {"event": event, "anomaly": anomaly, "risk": risk}

    def review(self, anomaly_id, action, note, reviewer):
        with self.lock:
            self._check()
            if action not in {"expected", "escalate", "request_verification", "close", "reopen", "propose_containment"} or not note or len(note.strip()) < 3 or not reviewer:
                raise ValueError("A supported review action, reviewer, and meaningful note are required")
            anomaly = self.store.get("aw_anomaly", anomaly_id)
            if not anomaly:
                raise ValueError("Unknown anomaly")
            note = redact(note[:2000])
            review = {"id": uid(), "anomaly_id": anomaly_id, "action": action, "note": note, "reviewer": redact(reviewer), "timestamp": stamp(), "mandatory_policy_unchanged": True}
            anomaly["review_history"].append(review)
            anomaly["status"] = {"expected": "expected", "escalate": "escalated", "request_verification": "verification_requested", "close": "closed", "reopen": "open", "propose_containment": "containment_proposed"}[action]
            anomaly["updated_at"] = stamp()
            if action in {"request_verification", "propose_containment"}:
                response = {"id": uid(), "anomaly_id": anomaly_id, "identity_id": anomaly["identity_id"], "tenant_id": self.policy["tenant_id"],
                            "authentication_session_id": anomaly["authentication_session_id"], "kind": "restrict_session" if action == "propose_containment" else "step_up",
                            "status": "pending", "created_at": stamp(), "requested_by": redact(reviewer), "note": note,
                            "expires_at": (utcnow() + timedelta(minutes=15)).isoformat(),
                            "scope": "Only the explicitly named synthetic authentication session; no account-wide disabling", "simulated": True}
                anomaly["response_id"] = response["id"]
                self.store.save("aw_response", response["id"], response)
            self.store.save("aw_review", review["id"], review)
            return self.store.save("aw_anomaly", anomaly_id, anomaly)

    def responses(self):
        with self.lock:
            self._check()
            return sorted(self.store.list("aw_response"), key=lambda item: item["created_at"], reverse=True)

    def approve_response(self, response_id, approved, reviewer, note=""):
        with self.lock:
            self._check()
            response = self.store.get("aw_response", response_id)
            if not response or response["status"] != "pending" or parsed(response.get("expires_at", response["created_at"])) <= utcnow() or not isinstance(approved, bool) or not reviewer:
                raise ValueError("A pending scoped response and explicit authority decision are required")
            session = self.store.get("aw_auth_session", response["authentication_session_id"])
            if not session or session["identity_id"] != response["identity_id"]:
                raise PermissionError("Response ownership does not match the authentication session")
            response.update(status="approved" if approved else "rejected", reviewed_by=redact(reviewer), reviewed_at=stamp())
            response["authority_review"] = {"reviewer": redact(reviewer), "note": redact(note[:2000]), "approved": approved, "timestamp": stamp()}
            if approved:
                session.update(status="restricted" if response["kind"] == "restrict_session" else "step_up_required", verified_until=None)
                self.store.save("aw_auth_session", session["id"], session)
                response["applied_at"] = stamp()
            return self.store.save("aw_response", response_id, response)

    def verify_session(self, identity_id, authentication_session_id, reviewer, note):
        with self.lock:
            self._check()
            self._get_identity(identity_id)
            session = self.store.get("aw_auth_session", authentication_session_id)
            if (not session or session["identity_id"] != identity_id or not reviewer or not note or len(note.strip()) < 3
                    or parsed(session["expires_at"]) <= utcnow() or session["status"] in {"ended", "pending_auth"}):
                raise PermissionError("Explicit scoped authority verification is required for a live authenticated session")
            session.update(status="active", verified_until=(utcnow() + timedelta(minutes=self.policy["verification_minutes"])).isoformat(),
                           verification={"reviewer": redact(reviewer), "note": redact(note[:2000]), "timestamp": stamp(), "method": "explicit mock administrator step-up", "simulated": True})
            return self.store.save("aw_auth_session", authentication_session_id, session)

    def gateway_findings(self, session, action):
        owner, auth_id = session.get("owner_identity_id"), session.get("authentication_session_id")
        if not owner and not auth_id:
            return []
        with self.lock:
            self._check()
            auth = self.store.get("aw_auth_session", auth_id)
            def finding(code, risk, explanation, hard):
                return {"module": "accountwatch", "rule_id": code, "risk_level": risk, "explanation": explanation, "hard": hard}
            if (not auth or auth["identity_id"] != owner or auth["tenant_id"] != self.policy["tenant_id"]
                    or parsed(auth["expires_at"]) <= utcnow() or auth["status"] in {"restricted", "ended", "pending_auth"}):
                return [finding("AW-SESSION-RESTRICTED", 3, "The explicitly bound synthetic authentication session is unavailable or restricted by an approved scoped response.", True)]
            if auth.get("verified_until") and parsed(auth["verified_until"]) > utcnow():
                return []
            sensitive = (action.get("tool") == "network" or action.get("operation") == "write"
                         or action.get("tool") == "tickets" or any(word in str(action.get("resource", "")).lower() for word in ("sensitive", "confidential", "secret", "credential", "config/")))
            if not sensitive:
                return []
            recent = [item for item in self.store.list("aw_anomaly") if item["identity_id"] == owner and item["authentication_session_id"] == auth_id
                      and item["status"] not in {"expected", "closed"} and utcnow() - parsed(item["timestamp"]) <= timedelta(minutes=self.policy["correlation_window_minutes"])]
            score = max((item["risk_score"] for item in recent), default=0)
            corroborated = any(len([reason for reason in item["reasons"] if reason["weight"] > 0]) >= 2 for item in recent)
            corroborated = corroborated or any("PRIVILEGE_POLICY_VIOLATION" in item["reason_codes"] for item in recent)
            if auth["status"] == "step_up_required" or (score >= self.policy["step_up_score"] and corroborated):
                return [finding("AW-IDENTITY-STEP-UP", 2, "Corroborated identity/session risk requires an exact human approval or administrator mock step-up before this sensitive agent operation. Existing capability and data policies still apply.", False)]
            return []

    def purge_expired(self, now=None):
        with self.lock:
            self._check()
            moment = now or utcnow()
            cutoff = moment - timedelta(days=self.policy["retention_days"])
            purged = 0
            for event in self.store.list("aw_event"):
                if not event.get("purged") and parsed(event["timestamp"]) < cutoff:
                    self.store.save("aw_event", event["id"], {"id": event["id"], "purged": True, "purged_at": moment.isoformat(), "retention_days": self.policy["retention_days"]})
                    purged += 1
            # Remove detailed copied evidence from investigation records too. Minimal
            # identifiers/status remain for auditable human-review lifecycle.
            for anomaly in self.store.list("aw_anomaly"):
                if parsed(anomaly["timestamp"]) < cutoff and not anomaly.get("evidence_purged"):
                    anomaly.update(reasons=[], explanation="Detailed telemetry expired under the configured retention policy.", evidence_purged=True, details_purged=True, purged_at=moment.isoformat())
                    self.store.save("aw_anomaly", anomaly["id"], anomaly)
            baseline_cutoff = moment - timedelta(days=self.policy["baseline_retention_days"])
            baselines_purged = 0
            for baseline in self.store.list("aw_baseline"):
                if baseline.get("status") != "expired" and parsed(baseline["created_at"]) < baseline_cutoff:
                    self.store.save("aw_baseline", baseline["identity_id"], {"id": baseline["id"], "identity_id": baseline["identity_id"],
                        "tenant_id": baseline["tenant_id"], "status": "expired", "sample_count": 0, "created_at": baseline["created_at"], "purged_at": moment.isoformat()})
                    baselines_purged += 1
            sessions_purged = 0
            for auth in self.store.list("aw_auth_session"):
                if not auth.get("details_purged") and parsed(auth["expires_at"]) < cutoff:
                    self.store.save("aw_auth_session", auth["id"], {"id": auth["id"], "identity_id": auth["identity_id"], "tenant_id": auth["tenant_id"],
                        "status": "expired", "expires_at": auth["expires_at"], "details_purged": True, "purged_at": moment.isoformat()})
                    sessions_purged += 1
            return {"purged_events": purged, "retention_days": self.policy["retention_days"], "audit_valid": self.store.verify()["valid"],
                    "purged_baselines": baselines_purged, "purged_auth_sessions": sessions_purged,
                    "audit_retention": "Minimized lifecycle identifiers and integrity digests remain; raw activity details are removed."}

    def demo(self, scenario):
        if scenario not in {"a", "b", "c", "d"}:
            raise ValueError("Use the enterprise demo for cross-module scenario E")
        self.seed()
        identity = self.identities()[0]
        baseline = self.baseline(identity["id"])
        session_id = f"demo-aw-{scenario}-{uuid4().hex[:10]}"
        moment = utcnow() - timedelta(minutes=3)
        common = {"identity_id": identity["id"], "authentication_session_id": session_id,
                  "application": baseline["applications"][0], "device_id": baseline["familiar_devices"][0], "region": baseline["regions"][0], "mfa_verified": True}
        steps = []
        def ingest(title, **fields):
            nonlocal moment
            moment += timedelta(seconds=20)
            result = self.ingest({**common, "timestamp": moment.isoformat(), **fields})
            steps.append({"title": title, "result": result})
            return result
        if scenario == "a":
            # Pick local 03:00 today, keeping the authentication session live.
            today = utcnow().astimezone(ZoneInfo(identity["timezone"])).replace(hour=3, minute=0, second=0, microsecond=0)
            if today > utcnow():
                today -= timedelta(days=1)
            # This demonstration uses an historical after-hours event; no agent binding.
            result = self.ingest({**common, "timestamp": today.isoformat(), "category": "auth_success", "approved_after_hours": True})
            steps.append({"title": "Approved after-hours work on a familiar verified device", "result": result})
            passed = result["anomaly"] is None
        elif scenario == "b":
            ingest("Establish an explicitly owned authentication session", category="auth_success")
            result = ingest("Observe personal sensitive-file volume deviation", category="file_access", resource_category="confidential", file_count=650, sensitive_file_count=350, data_mb=400)
            passed = result["risk"]["score"] >= 50
        elif scenario == "c":
            common.update(device_id="unfamiliar-synthetic-device", mfa_verified=False)
            ingest("Unfamiliar-device authentication", category="auth_success")
            result = ingest("Correlate a subsequent privileged change in the same session", category="privilege_change", privilege="admin")
            passed = result["risk"]["score"] >= 70
        else:
            common.update(device_id="unfamiliar-synthetic-device", mfa_verified=False)
            ingest("Repeated authentication failures", category="auth_failure", failed_attempts=8)
            ingest("Successful login in the explicitly same authentication session", category="auth_success")
            result = ingest("Correlate subsequent confidential resource access", category="file_access", resource_category="confidential", file_count=650, sensitive_file_count=350)
            passed = result["risk"]["score"] >= 70 and any(item["code"] == "POSSIBLE_TAKEOVER_SEQUENCE" for item in result["risk"]["reasons"])
        return {"scenario": scenario, "steps": steps, "passed": bool(passed), "simulated": True,
                "note": "Synthetic metadata demonstration. An anomaly is not proof of compromise; no account is automatically disabled."}

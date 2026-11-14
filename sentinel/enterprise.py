"""Explainable cross-module projections; explicit ownership, never time-only links.

All connectors are mock mappings. No method in this module authorizes a tool or
changes employee permissions; independent AgentGuard policy remains authoritative.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .core import Engine

LEVELS = ("informational", "low", "moderate", "high", "critical")
AG_SCORE = {0: 10, 1: 35, 2: 60, 3: 80, 4: 95}


def _time(value: Any) -> datetime | None:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return result if result.tzinfo else None
    except (ValueError, TypeError):
        return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Enterprise:
    def __init__(self, engine: Engine):
        self.engine, self.store, self.aw = engine, engine.store, engine.accountwatch

    def _require(self):
        if not self.store.verify()["valid"]:
            raise RuntimeError("Audit integrity unavailable; enterprise operations paused")

    def _policy(self) -> dict:
        policy = getattr(self.aw, "policy", {})
        return policy if isinstance(policy, dict) else {}

    def _level(self, score: float) -> str:
        thresholds = self._policy().get("thresholds", [])
        if isinstance(thresholds, list):
            for item in thresholds:
                if isinstance(item, dict) and item.get("min", 101) <= score <= item.get("max", -1):
                    return str(item.get("label", "informational")).lower()
        return LEVELS[4 if score >= 90 else 3 if score >= 70 else 2 if score >= 50 else 1 if score >= 25 else 0]

    @staticmethod
    def _score(item: dict) -> int:
        risk = item.get("risk", {})
        value = item.get("risk_score", item.get("score", risk.get("score", 0) if isinstance(risk, dict) else 0))
        try:
            return max(0, min(100, int(value)))
        except (ValueError, TypeError):
            return 0

    def _review_state(self, record: dict) -> dict:
        reviewed = self.store.get("enterprise_review", record["id"])
        if reviewed:
            record.update(status=reviewed["status"], investigation_status=reviewed["status"],
                          reviews=reviewed.get("reviews", []), updated_at=reviewed["updated_at"])
        return record

    def correlated(self) -> list[dict]:
        with self.store.lock:
            self._require()
            sessions = {s["id"]: s for s in self.store.list("session")}
            auth_sessions = {s["id"]: s for s in self.store.list("aw_auth_session")}
            identities = {i["id"]: i for i in self.store.list("aw_identity")}
            aw_events = {e["id"]: e for e in self.store.list("aw_event") if not e.get("purged")}
            anomalies = self.store.list("aw_anomaly")
            groups: dict[tuple[str, str], dict] = {}
            seconds = int(self._policy().get("correlation_window_minutes", 60)) * 60
            for event in self.store.list("event"):
                if event.get("risk_level", 0) < 2:
                    continue
                session = sessions.get(event.get("session_id"))
                if not session or event.get("agent_id") != session.get("agent_id"):
                    continue
                owner, auth_id = session.get("owner_identity_id"), session.get("authentication_session_id")
                auth = auth_sessions.get(auth_id)
                identity = identities.get(owner)
                if not owner or not auth_id or not auth or not identity or auth.get("identity_id") != owner:
                    continue
                tenant = identity.get("tenant_id", "sentinel-demo")
                if auth.get("tenant_id", tenant) != tenant:
                    continue
                event_time = _time(event.get("timestamp"))
                matching = []
                for anomaly in anomalies:
                    source = aw_events.get(anomaly.get("event_id"), {})
                    anomaly_auth = anomaly.get("authentication_session_id") or source.get("authentication_session_id")
                    when = _time(anomaly.get("timestamp", anomaly.get("created_at")))
                    if (anomaly.get("identity_id") == owner and anomaly_auth == auth_id
                            and anomaly.get("tenant_id", tenant) == tenant and event_time and when
                            and abs((event_time - when).total_seconds()) <= seconds):
                        matching.append(anomaly)
                if not matching:
                    continue
                group = groups.setdefault((owner, auth_id), {"events": [], "anomalies": {}, "sessions": {}})
                group["events"].append(event)
                group["sessions"][session["id"]] = session
                group["anomalies"].update({a["id"]: a for a in matching})
            results = []
            for (owner, auth_id), group in groups.items():
                events = sorted(group["events"], key=lambda e: e["timestamp"], reverse=True)
                latest = events[0]
                correlated_id = "corr-" + hashlib.sha256(f"{owner}:{auth_id}".encode()).hexdigest()[:20]
                anomaly_list = list(group["anomalies"].values())
                score = max([AG_SCORE.get(int(e.get("risk_level", 0)), 0) for e in events]
                            + [self._score(a) for a in anomaly_list])
                edges = [{"source": owner, "type": "authenticated_as", "target": auth_id,
                          "evidence": "Persisted authentication-session identity ownership; not inferred from time."}]
                for session in group["sessions"].values():
                    edges.append({"source": auth_id, "type": "owns_agent_session", "target": session["id"],
                                  "evidence": "Administrator-issued immutable owner and authentication-session binding."})
                    if session.get("parent_session_id"):
                        edges.append({"source": session["parent_session_id"], "type": "delegated_to", "target": session["id"],
                                      "evidence": "Server-recorded delegation lineage with inherited ownership scope."})
                for event in events:
                    requested = event.get("requested_action", {})
                    tool = f"{requested.get('tool', 'unknown')}:{requested.get('operation', 'unknown')}"
                    resource = requested.get("resource") or requested.get("destination") or "unspecified-resource"
                    tool_node = f"{event['id']}:tool"
                    edges.extend([
                        {"source": event["session_id"], "type": "requested_tool", "target": tool_node, "label": tool,
                         "evidence": f"Authenticated AgentGuard event {event['id']}"},
                        {"source": tool_node, "type": "targeted_resource", "target": resource,
                         "evidence": "Sanitized resource metadata from the intercepted request."},
                        {"source": tool_node, "type": "recorded_security_event", "target": event["id"],
                         "evidence": "Durable policy-decision event."},
                        {"source": event["id"], "type": "enforcement_decision", "target": event["decision"],
                         "evidence": "Mandatory authorization remains independent of behavioral inference."},
                    ])
                record = {"id": correlated_id, "module": "correlated", "classification": "correlated_investigation",
                          "incident_type": "identity_agent_association", "status": "open", "investigation_status": "open",
                          "tenant_id": identities[owner].get("tenant_id", "sentinel-demo"),
                          "risk_score": score, "risk_level": self._level(score), "identity_id": owner,
                          "identity_name": identities[owner].get("name", owner), "agent_id": latest["agent_id"],
                          "agent_ids": sorted({e["agent_id"] for e in events}), "session_id": latest["session_id"],
                          "session_ids": sorted(group["sessions"]), "authentication_session_id": auth_id,
                          "timestamp": latest["timestamp"], "event_ids": [e["id"] for e in events],
                          "anomaly_ids": sorted(group["anomalies"]), "evidence": edges, "edges": edges,
                          "agent_events": events, "anomalies": anomaly_list,
                          "explanation": "Explicit identity and authentication-session bindings connect behavioral anomalies to agent policy decisions. Timing is corroborating context; the relationship does not establish causation or confirmed account compromise.",
                          "recommended_responses": ["Review the linked evidence", "Request scoped step-up verification", "Approve a synthetic agent repair before restoration"],
                          "relationship_basis": "explicit_owner_and_authentication_session", "confirmed_compromise": False,
                          "score_is_probability": False}
                results.append(self._review_state(record))
            return self.engine.redact(sorted(results, key=lambda r: r["timestamp"], reverse=True))

    def command(self, filters: dict | None = None) -> dict:
        with self.store.lock:
            self._require()
            filters = filters or {}
            snapshot = self.engine.snapshot()
            identities = self.aw.identities()
            rows = []
            sessions = {s["id"]: s for s in self.store.list("session")}
            for event in snapshot["events"]:
                if event["risk_level"] < 2:
                    continue
                session = sessions.get(event["session_id"], {})
                score = AG_SCORE[event["risk_level"]]
                rows.append(self._review_state({**event, "module": "agentguard",
                    "classification": "policy_violation" if event["risk_level"] >= 3 else "approval_request",
                    "incident_type": "tool_policy_violation" if event["risk_level"] >= 3 else "authorization_review",
                    "agentguard_risk_level": event["risk_level"], "risk_score": score, "risk_level": self._level(score),
                    "identity_id": session.get("owner_identity_id"), "authentication_session_id": session.get("authentication_session_id"),
                    "status": "resolved" if event.get("remediation_status") == "restored_after_review" else "open",
                    "investigation_status": "resolved" if event.get("remediation_status") == "restored_after_review" else "open"}))
            for anomaly in self.aw.anomalies():
                score = self._score(anomaly)
                rows.append(self._review_state({**anomaly, "module": "accountwatch", "classification": "behavioral_anomaly",
                    "incident_type": anomaly.get("incident_type", "behavioral_deviation"), "risk_score": score,
                    "risk_level": self._level(score), "timestamp": anomaly.get("timestamp", anomaly.get("created_at")),
                    "status": anomaly.get("status", "open"), "investigation_status": anomaly.get("status", "open"),
                    "explanation": anomaly.get("explanation", "Behavioral deviation requires contextual analyst review; it is not proof of compromise."),
                    "confirmed_compromise": False}))
            correlated = self.correlated()
            rows.extend(correlated)
            all_rows = sorted(rows, key=lambda row: str(row.get("timestamp", "")), reverse=True)
            filtered = self._filter(all_rows, filters)
            open_status = {"open", "pending", "pending_review", "escalated", "verification_requested", "containment_proposed"}
            active_anomalies = [a for a in self.aw.anomalies() if a.get("status", "open") in open_status]
            high_threshold = next((band["min"] for band in self._policy().get("thresholds", []) if band.get("label") == "high"), 70)
            counts = {"total_incidents": len(all_rows), "filtered_incidents": len(filtered),
                      "agentguard_incidents": sum(r["module"] == "agentguard" for r in all_rows),
                      "accountwatch_anomalies": len(self.aw.anomalies()), "active_anomalies": len(active_anomalies),
                      "correlated_incidents": len(correlated), "active_agent_sessions": snapshot["metrics"]["active_agents"],
                      "active_agents": snapshot["metrics"]["active_agents"], "monitored_identities": len(identities),
                      "blocked_actions": snapshot["metrics"]["blocked_actions"], "policy_enforcements": len(snapshot["events"]), "pending_approvals": snapshot["metrics"]["pending_approvals"] + sum(r.get("status") == "pending" for r in self.aw.responses()),
                      "agentguard_pending_approvals": snapshot["metrics"]["pending_approvals"],
                      "accountwatch_pending_approvals": sum(r.get("status") == "pending" for r in self.aw.responses()),
                      "pending_reviews": sum(r.get("status") in open_status for r in all_rows),
                      "resolved_incidents": sum(r.get("status") in {"closed", "resolved", "expected"} for r in all_rows),
                      "high_priority_alerts": sum(r["risk_score"] >= high_threshold and r.get("status") in open_status for r in all_rows),
                      "security_events": len(snapshot["events"]) + len(self.store.list("aw_event"))}
            daily: dict[str, Counter] = {}
            for row in all_rows:
                day = str(row.get("timestamp", ""))[:10]
                counter = daily.setdefault(day, Counter())
                counter[row["module"]] += 1
            trends = [{"date": day, "agentguard": counter["agentguard"], "accountwatch": counter["accountwatch"],
                       "correlated": counter["correlated"], "total": sum(counter.values())}
                      for day, counter in sorted(daily.items())]
            response = {"counts": counts, "incidents": filtered[:500], "correlated": correlated, "trends": trends,
                        "identities": identities, "agents": snapshot["agents"], "health": snapshot["health"],
                        "policy": {"thresholds": self._policy().get("thresholds", []), "agentguard_visual_mapping": AG_SCORE,
                                   "score_is_probability": False}, "filters": filters, "connectors": self.connectors(),
                        "posture": "review_required" if counts["high_priority_alerts"] else "normal_operations",
                        "note": "Synthetic security metadata only. Behavioral anomalies and confirmed policy violations remain separate classifications."}
            return self.engine.redact(response)

    def _filter(self, rows: list[dict], filters: dict) -> list[dict]:
        now = datetime.now(timezone.utc)
        span = {"1h": timedelta(hours=1), "24h": timedelta(days=1), "7d": timedelta(days=7), "30d": timedelta(days=30)}.get(filters.get("time_range"))
        selected = []
        for row in rows:
            if any(filters.get(key) not in (None, "", "all") and row.get(key) != filters[key]
                   for key in ("module", "risk_level", "identity_id", "agent_id", "incident_type", "status")):
                continue
            stamp = _time(row.get("timestamp"))
            if span and (not stamp or stamp < now - span):
                continue
            query = str(filters.get("search", "")).strip().lower()
            if query and query not in " ".join(str(row.get(key, "")) for key in
                                              ("id", "identity_id", "agent_id", "classification", "explanation")).lower():
                continue
            selected.append(row)
        return selected

    def review(self, incident_id: str, action: str, note: str, reviewer: str) -> dict:
        with self.store.lock:
            self._require()
            if action not in {"expected", "escalate", "request_verification", "close", "reopen"}:
                raise ValueError("Unsupported investigation review action")
            if not reviewer or not isinstance(note, str) or not 3 <= len(note.strip()) <= 2000:
                raise ValueError("A meaningful bounded analyst note is required")
            available = {record["id"]: record for record in self.command()["incidents"]}
            # Correlations remain reviewable even when the command table is capped.
            available.update({record["id"]: record for record in self.correlated()})
            record = available.get(incident_id)
            if not record:
                raise ValueError("Unknown reviewable incident")
            if record["module"] == "accountwatch":
                return self.aw.review(incident_id, action, note, reviewer)
            if record["module"] == "agentguard":
                self.engine.review_incident(incident_id, reviewer, note)
            old = self.store.get("enterprise_review", incident_id) or {"id": incident_id, "reviews": []}
            status = {"expected": "expected", "escalate": "escalated", "request_verification": "verification_requested",
                      "close": "closed", "reopen": "open"}[action]
            stamp = _now()
            old.update(status=status, updated_at=stamp, tenant_id="sentinel-demo")
            old["reviews"].append({"action": action, "note": self.engine.redact(note), "reviewer": self.engine.redact(reviewer),
                                   "timestamp": stamp, "mandatory_policy_unchanged": True})
            self.store.save("enterprise_review", incident_id, old)
            return self._review_state(record)

    def connectors(self) -> list[dict]:
        products = [
            ("duo", "Cisco Duo", "Identity verification and adaptive access", ["authentication context", "mock step-up request"]),
            ("xdr", "Cisco XDR", "Cross-domain investigation", ["correlated incident", "evidence lineage"]),
            ("secure_access", "Cisco Secure Access", "Zero-trust access", ["policy decision", "scoped response proposal"]),
            ("identity_intelligence", "Cisco Identity Intelligence", "Identity risk context", ["behavioral deviation", "identity posture"]),
            ("splunk", "Cisco Splunk", "Security event analytics", ["sanitized audit event", "investigation lifecycle"]),
        ]
        activities = [event for event in self.store.list("aw_event") if not event.get("purged")]
        sources = {
            "duo": [event for event in activities if event.get("category") in {"auth_success", "auth_failure"}],
            "xdr": self.correlated(),
            "secure_access": self.store.list("event"),
            "identity_intelligence": self.store.list("aw_anomaly"),
            "splunk": self.store.list("alert"),
        }
        return self.engine.redact([{"id": identifier, "name": name, "domain": domain, "status": "mock", "mode": "local_simulation",
                 "official_integration": False, "connected_to_cisco": False, "proposed_mappings": mappings,
                 "description": "Proposed integration opportunity; this local projection is not a live Cisco connection or an official product API schema.",
                 "delivery_count": 0, "mock_projection_count": len(sources[identifier]), "requires_credentials": False,
                 "preview_payload": {"adapter": identifier, "synthetic": True, "projection_only": True,
                                     "event_ids": [event["id"] for event in sources[identifier][-5:]],
                                     "schema": "sentinel-proposed-mapping-v1"}}
                for identifier, name, domain, mappings in products])

    def demo(self, phase: str = "all", complete_recovery: bool = False) -> dict:
        from .enterprise_demo import run_enterprise_demo
        return run_enterprise_demo(self.engine, phase, complete_recovery=complete_recovery)

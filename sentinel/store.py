"""SQLite records with a keyed, externally anchored audit chain.

The host process and files holding the audit key are trusted. Database-only edits,
record modification and truncation are detected. An OS administrator who controls
both key and state can forge history; this is not remote immutable storage.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from pathlib import Path
from typing import Any

from sqlalchemy import Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


class Base(DeclarativeBase):
    pass


class Record(Base):
    __tablename__ = "records"
    key: Mapped[str] = mapped_column(String, primary_key=True)
    kind: Mapped[str] = mapped_column(String, index=True)
    body: Mapped[str] = mapped_column(Text)


class Audit(Base):
    __tablename__ = "audit"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True)
    payload: Mapped[str] = mapped_column(Text)
    previous_hash: Mapped[str] = mapped_column(String)
    digest: Mapped[str] = mapped_column(String)


class Store:
    def __init__(self, directory: Path):
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.key_path = directory / "audit.key"
        if not self.key_path.exists():
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(os.urandom(32))
        self.key = self.key_path.read_bytes()
        if len(self.key) != 32:
            raise RuntimeError("Invalid local audit key; execution disabled")
        self.anchor_path = directory / "audit.head"
        self.db_path = directory / "sentinel.db"
        self.db = create_engine(f"sqlite:///{self.db_path}", connect_args={"check_same_thread": False})
        Base.metadata.create_all(self.db)
        os.chmod(self.db_path, 0o600)
        if not self.anchor_path.exists():
            with Session(self.db) as db:
                if db.scalar(select(Audit.seq).limit(1)) is not None:
                    raise RuntimeError("Missing audit anchor on populated database")
            self._write_anchor(0, "0" * 64)

    def digest(self, value: Any) -> str:
        return hmac.new(self.key, canonical(value).encode(), hashlib.sha256).hexdigest()

    def _write_anchor(self, count: int, head: str) -> None:
        value = {"count": count, "head": head}
        value["signature"] = self.digest(value)
        temporary = self.anchor_path.with_suffix(".head.tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.anchor_path)

    def _public_audit(self, body: dict) -> dict:
        # Tokens are stored only as hashes in session records, never in audit views.
        return {key: value for key, value in body.items() if key not in {"token_hash"}}

    def _audit_snapshot(self, kind: str, body: dict) -> dict:
        if kind == "aw_event":
            # Telemetry detail has its own retention clock. Never duplicate it in
            # immutable history: the state digest still detects tampering, while
            # retention can replace the live record with a minimal tombstone.
            return {key: body[key] for key in ("id", "timestamp", "purged", "purged_at") if key in body}
        if kind == "aw_anomaly":
            return {key: body[key] for key in ("id", "timestamp", "status", "risk_score", "reason_codes", "details_purged", "purged_at") if key in body}
        if kind == "aw_baseline":
            return {key: body[key] for key in ("id", "identity_id", "created_at", "sample_count", "training_split", "purged", "purged_at") if key in body}
        if kind == "aw_auth_session":
            return {key: body[key] for key in ("id", "identity_id", "tenant_id", "status", "created_at", "expires_at", "purged", "purged_at") if key in body}
        return self._public_audit(body)

    def save(self, kind: str, record_id: str, body: dict) -> dict:
        """Commit record and immutable snapshot together before advancing anchor."""
        with self.lock:
            check = self.verify()
            if not check["valid"]:
                raise RuntimeError("Audit integrity failure; all mutations and tool execution disabled")
            record_key = f"{kind}:{record_id}"
            payload = {
                "kind": kind,
                "record_id": record_id,
                "record": self._audit_snapshot(kind, body),
                "state_digest": self.digest(body),
            }
            with Session(self.db) as db:
                last = db.scalar(select(Audit).order_by(Audit.seq.desc()).limit(1))
                count, previous = (last.seq, last.digest) if last else (0, "0" * 64)
                content = canonical(payload)
                digest = self.digest({"seq": count + 1, "previous_hash": previous, "payload": content})
                record = db.get(Record, record_key)
                if record:
                    record.body = canonical(body)
                else:
                    db.add(Record(key=record_key, kind=kind, body=canonical(body)))
                db.add(Audit(seq=count + 1, payload=content, previous_hash=previous, digest=digest))
                db.commit()
            # A crash between SQLite commit and this anchor advancement fails closed
            # on the next verification. Recovery needs trusted external review.
            self._write_anchor(count + 1, digest)
            return body

    def get(self, kind: str, record_id: str) -> dict | None:
        with Session(self.db) as db:
            record = db.get(Record, f"{kind}:{record_id}")
            return json.loads(record.body) if record else None

    def list(self, kind: str) -> list[dict]:
        with Session(self.db) as db:
            records = db.scalars(select(Record).where(Record.kind == kind)).all()
            return [json.loads(record.body) for record in records]

    def verify(self) -> dict:
        with self.lock:
            try:
                anchor = json.loads(self.anchor_path.read_text())
                signature = anchor.pop("signature")
                if not hmac.compare_digest(signature, self.digest(anchor)):
                    return {"valid": False, "count": 0, "reason": "Anchor signature mismatch"}
                previous, count = "0" * 64, 0
                latest: dict[str, str] = {}
                with Session(self.db) as db:
                    for entry in db.scalars(select(Audit).order_by(Audit.seq)):
                        count += 1
                        expected = self.digest({"seq": count, "previous_hash": previous, "payload": entry.payload})
                        if entry.seq != count or entry.previous_hash != previous or not hmac.compare_digest(expected, entry.digest):
                            return {"valid": False, "count": count - 1, "reason": "Audit chain mismatch"}
                        payload = json.loads(entry.payload)
                        latest[f"{payload['kind']}:{payload['record_id']}"] = payload["state_digest"]
                        previous = entry.digest
                    records = db.scalars(select(Record)).all()
                    if len(records) != len(latest):
                        return {"valid": False, "count": count, "reason": "Record set mismatch"}
                    for record in records:
                        actual = self.digest(json.loads(record.body))
                        expected = latest.get(record.key, "")
                        if not hmac.compare_digest(actual, expected):
                            return {"valid": False, "count": count, "reason": "Persisted record modified"}
                if anchor["count"] != count or anchor["head"] != previous:
                    return {"valid": False, "count": count, "reason": "Audit truncation or anchor mismatch"}
                return {"valid": True, "count": count, "head": previous, "mode": "local-keyed-anchor"}
            except (OSError, ValueError, KeyError, TypeError):
                return {"valid": False, "count": 0, "reason": "Audit unreadable"}

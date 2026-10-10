"""Append-only, hash-chained audit log.

Each entry stores the hash of the previous entry (`prev_hash`) and its own
hash (`entry_hash`), computed over a canonical JSON encoding of all its
fields. Editing, deleting, inserting or reordering any entry changes a hash
that a later entry depends on, so `verify_chain()` can detect it.

Defence in depth against modification:
  1. The application exposes no update/delete path for entries.
  2. An ORM flush hook refuses to update or delete AuditEntry rows.
  3. Database triggers reject UPDATE/DELETE (and TRUNCATE on PostgreSQL).
  4. Anything that gets past 1-3 is detected by verify_chain().
"""

import hashlib
import json
from dataclasses import dataclass, field

from sqlalchemy import event, select, text
from sqlalchemy.orm import Session

from . import db
from .models import AuditEntry, utcnow_iso

GENESIS_HASH = "0" * 64
_PG_LOCK_ID = 7_400_001  # arbitrary constant for pg_advisory_xact_lock


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_entry_hash(*, id, timestamp, actor, action, evidence_id, details, prev_hash):
    payload = canonical_json(
        {
            "id": id,
            "timestamp": timestamp,
            "actor": actor,
            "action": action,
            "evidence_id": evidence_id,
            "details": details,
            "prev_hash": prev_hash,
        }
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append(action, actor, evidence_id=None, details=None):
    """Add an entry to the current transaction. The caller commits, so the
    log entry and the change it describes succeed or fail together."""
    session = db.session
    if session.get_bind().dialect.name == "postgresql":
        # Serialise appenders so two requests cannot read the same tail.
        session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _PG_LOCK_ID})

    last = session.execute(
        select(AuditEntry.id, AuditEntry.entry_hash).order_by(AuditEntry.id.desc()).limit(1)
    ).first()
    prev_id, prev_hash = (last.id, last.entry_hash) if last else (0, GENESIS_HASH)

    fields = {
        "id": prev_id + 1,
        "timestamp": utcnow_iso(),
        "actor": actor,
        "action": action,
        "evidence_id": evidence_id,
        "details": canonical_json(details or {}),
        "prev_hash": prev_hash,
    }
    entry = AuditEntry(**fields, entry_hash=compute_entry_hash(**fields))
    session.add(entry)
    session.flush()
    return entry


@dataclass
class ChainVerification:
    ok: bool = True
    entries_checked: int = 0
    head_hash: str = GENESIS_HASH
    errors: list = field(default_factory=list)  # [(entry_id, message)]

    def fail(self, entry_id, message):
        self.ok = False
        self.errors.append((entry_id, message))

    def summary(self):
        if self.ok:
            return f"OK: {self.entries_checked} entries, head {self.head_hash}"
        lines = [f"FAILED: {len(self.errors)} problem(s) in {self.entries_checked} entries"]
        lines += [f"  entry {eid}: {msg}" for eid, msg in self.errors]
        return "\n".join(lines)


def verify_chain(expected_head=None):
    """Walk the whole log, recomputing every hash and link.

    `expected_head` is an externally recorded head hash (e.g. printed on an
    earlier certificate). If given, the chain must still contain it; this is
    what detects truncation of the most recent entries.
    """
    result = ChainVerification()
    prev_hash = GENESIS_HASH
    expected_id = 1
    seen_expected_head = expected_head is None

    for e in db.session.execute(select(AuditEntry).order_by(AuditEntry.id)).scalars():
        result.entries_checked += 1
        if e.id != expected_id:
            result.fail(e.id, f"sequence gap: expected id {expected_id}")
        if e.prev_hash != prev_hash:
            result.fail(e.id, "prev_hash does not match previous entry (entry removed, inserted or reordered)")
        recomputed = compute_entry_hash(
            id=e.id,
            timestamp=e.timestamp,
            actor=e.actor,
            action=e.action,
            evidence_id=e.evidence_id,
            details=e.details,
            prev_hash=e.prev_hash,
        )
        if recomputed != e.entry_hash:
            result.fail(e.id, "entry_hash mismatch (entry contents modified)")
        if e.entry_hash == expected_head:
            seen_expected_head = True
        prev_hash = e.entry_hash
        expected_id = e.id + 1

    result.head_hash = prev_hash
    if not seen_expected_head:
        result.fail(None, f"expected head {expected_head} not found (log truncated or replaced)")
    return result


def entries_for_evidence(evidence_id):
    return (
        db.session.execute(
            select(AuditEntry).where(AuditEntry.evidence_id == evidence_id).order_by(AuditEntry.id)
        )
        .scalars()
        .all()
    )


@event.listens_for(Session, "before_flush")
def _block_audit_mutation(session, flush_context, instances):
    for obj in list(session.dirty) + list(session.deleted):
        if isinstance(obj, AuditEntry):
            raise PermissionError("audit_log is append-only")


_SQLITE_TRIGGERS = [
    """CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
       BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END""",
    """CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
       BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END""",
]

_PG_TRIGGERS = [
    """CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS trigger AS $$
       BEGIN RAISE EXCEPTION 'audit_log is append-only'; END; $$ LANGUAGE plpgsql""",
    "DROP TRIGGER IF EXISTS audit_log_no_mutation ON audit_log",
    """CREATE TRIGGER audit_log_no_mutation BEFORE UPDATE OR DELETE ON audit_log
       FOR EACH ROW EXECUTE FUNCTION audit_log_append_only()""",
    "DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log",
    """CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
       FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only()""",
]


def install_append_only_triggers():
    dialect = db.engine.dialect.name
    statements = {"sqlite": _SQLITE_TRIGGERS, "postgresql": _PG_TRIGGERS}.get(dialect, [])
    with db.engine.begin() as conn:
        for stmt in statements:
            conn.execute(text(stmt))

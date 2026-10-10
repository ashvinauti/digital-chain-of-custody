"""Append-only, hash-chained, signed audit log.

Each entry stores the hash of the previous entry (`prev_hash`) and its own
hash (`entry_hash`), computed over a canonical JSON encoding of all its
fields. Editing, deleting, inserting or reordering any entry changes a hash
that a later entry depends on, so `verify_chain()` can detect it.

Each entry_hash is also signed with the server's Ed25519 key (signing.py).
Someone who can write to the database but not read the key cannot rebuild
a valid chain, even by recomputing every hash.

Anchors close the remaining gap, deleting the newest entries: `anchor()`
appends a signed {entry_id, head_hash} line to ANCHOR_FILE, which should live
outside the database (ideally write-once or off-host storage). Every anchor
must still match the chain, so a truncated log no longer verifies.

Defence in depth against modification:
  1. The application exposes no update/delete path for entries.
  2. An ORM flush hook refuses to update or delete AuditEntry rows.
  3. Database triggers reject UPDATE/DELETE (and TRUNCATE on PostgreSQL).
  4. Anything that gets past 1-3 is detected by verify_chain().
"""

import hashlib
import json
import os
from dataclasses import dataclass, field

from flask import current_app
from sqlalchemy import event, select, text
from sqlalchemy.orm import Session

from . import db
from .models import AuditEntry, utcnow_iso

GENESIS_HASH = "0" * 64
_PG_LOCK_ID = 7_400_001  # arbitrary constant for pg_advisory_xact_lock


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def signer():
    return current_app.extensions["signer"]


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
    entry_hash = compute_entry_hash(**fields)
    s = signer()
    entry = AuditEntry(**fields, entry_hash=entry_hash, key_id=s.key_id, signature=s.sign(entry_hash.encode()))
    session.add(entry)
    session.flush()
    return entry


# --- anchors -----------------------------------------------------------------


def _anchor_payload(a):
    return canonical_json({k: a[k] for k in ("entry_id", "head_hash", "timestamp", "key_id")}).encode()


def anchor():
    """Append a signed record of the current head to ANCHOR_FILE.

    Call only after a commit, so the anchored entry is durable. Returns the
    anchor dict, or None if the log is empty or the head is already anchored.
    """
    last = db.session.execute(
        select(AuditEntry.id, AuditEntry.entry_hash).order_by(AuditEntry.id.desc()).limit(1)
    ).first()
    if last is None:
        return None
    previous = load_anchors()
    if previous and previous[-1][1] and previous[-1][1].get("entry_id") == last.id:
        return None
    s = signer()
    a = {"entry_id": last.id, "head_hash": last.entry_hash, "timestamp": utcnow_iso(), "key_id": s.key_id}
    a["signature"] = s.sign(_anchor_payload(a))
    path = current_app.config["ANCHOR_FILE"]
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    # One short line in append mode: concurrent writers don't interleave.
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(canonical_json(a) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return a


def load_anchors():
    path = current_app.config["ANCHOR_FILE"]
    if not os.path.exists(path):
        return []
    anchors = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if line.strip():
                try:
                    anchors.append((lineno, json.loads(line)))
                except ValueError:
                    anchors.append((lineno, None))
    return anchors


# --- verification ------------------------------------------------------------


@dataclass
class ChainVerification:
    ok: bool = True
    entries_checked: int = 0
    anchors_checked: int = 0
    head_hash: str = GENESIS_HASH
    head_id: int = 0
    errors: list = field(default_factory=list)  # [(entry_id or None, message)]

    def fail(self, entry_id, message):
        self.ok = False
        self.errors.append((entry_id, message))

    def summary(self):
        if self.ok:
            return (
                f"OK: {self.entries_checked} entries (hashes, links and signatures), "
                f"{self.anchors_checked} anchors, head {self.head_hash}"
            )
        lines = [f"FAILED: {len(self.errors)} problem(s) in {self.entries_checked} entries"]
        lines += [f"  entry {eid}: {msg}" if eid else f"  {msg}" for eid, msg in self.errors]
        return "\n".join(lines)


def verify_chain(expected_head=None, check_anchors=True):
    """Walk the whole log, recomputing every hash, link and signature, then
    check every anchor against it.

    `expected_head` is a head hash recorded elsewhere (e.g. printed on an
    earlier certificate); if given, the chain must still contain it.
    """
    s = signer()
    result = ChainVerification()
    prev_hash = GENESIS_HASH
    expected_id = 1
    hashes = {}  # id -> entry_hash, for anchor checks

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
        if e.key_id != s.key_id:
            result.fail(e.id, f"signed by unknown key {e.key_id}")
        elif not s.verify(e.signature, e.entry_hash.encode()):
            result.fail(e.id, "invalid signature (entry forged or re-hashed without the signing key)")
        hashes[e.id] = e.entry_hash
        prev_hash = e.entry_hash
        expected_id = e.id + 1

    result.head_hash = prev_hash
    result.head_id = expected_id - 1
    if expected_head is not None and expected_head not in hashes.values():
        result.fail(None, f"expected head {expected_head} not found (log truncated or replaced)")

    if check_anchors:
        for lineno, a in load_anchors():
            result.anchors_checked += 1
            where = f"anchor line {lineno}"
            if not a or not {"entry_id", "head_hash", "timestamp", "key_id", "signature"} <= a.keys():
                result.fail(None, f"{where}: malformed")
            elif a["key_id"] != s.key_id or not s.verify(a["signature"], _anchor_payload(a)):
                result.fail(None, f"{where}: invalid signature (anchor file tampered)")
            elif a["entry_id"] not in hashes:
                result.fail(None, f"{where}: anchored entry {a['entry_id']} is missing (log truncated)")
            elif hashes[a["entry_id"]] != a["head_hash"]:
                result.fail(a["entry_id"], f"{where}: entry no longer matches its anchored hash")
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

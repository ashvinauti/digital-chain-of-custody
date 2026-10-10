import io
import json

import pytest
from pypdf import PdfReader
from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError

from app import audit, db
from app.models import AuditEntry


def _seed(n=5):
    for i in range(n):
        audit.append("test.event", "tester", details={"i": i})
    db.session.commit()


def _raw(sql, **params):
    """Bypass the ORM and the append-only triggers, as an attacker with
    direct database access would."""
    with db.engine.begin() as conn:
        conn.execute(text("DROP TRIGGER IF EXISTS audit_log_no_update"))
        conn.execute(text("DROP TRIGGER IF EXISTS audit_log_no_delete"))
        conn.execute(text(sql), params)
    db.session.expire_all()


def test_each_entry_links_to_previous(app):
    _seed()
    entries = db.session.execute(select(AuditEntry).order_by(AuditEntry.id)).scalars().all()
    assert entries[0].prev_hash == audit.GENESIS_HASH
    for prev, cur in zip(entries, entries[1:]):
        assert cur.prev_hash == prev.entry_hash
        assert cur.id == prev.id + 1
    result = audit.verify_chain()
    assert result.ok, result.summary()
    assert result.head_hash == entries[-1].entry_hash


def test_entry_hash_covers_every_field(app):
    _seed(1)
    e = db.session.execute(select(AuditEntry).order_by(AuditEntry.id.desc())).scalars().first()
    base = dict(id=e.id, timestamp=e.timestamp, actor=e.actor, action=e.action,
                evidence_id=e.evidence_id, details=e.details, prev_hash=e.prev_hash)
    assert audit.compute_entry_hash(**base) == e.entry_hash
    for key, value in [("id", 99), ("timestamp", "x"), ("actor", "x"), ("action", "x"),
                       ("evidence_id", 42), ("details", "{}"), ("prev_hash", "f" * 64)]:
        assert audit.compute_entry_hash(**{**base, key: value}) != e.entry_hash, key


def test_orm_refuses_update_and_delete(app):
    _seed(1)
    e = db.session.execute(select(AuditEntry)).scalars().first()
    e.actor = "mallory"
    with pytest.raises(PermissionError):
        db.session.commit()
    db.session.rollback()
    db.session.delete(db.session.execute(select(AuditEntry)).scalars().first())
    with pytest.raises(PermissionError):
        db.session.commit()
    db.session.rollback()


@pytest.mark.parametrize("sql", ["UPDATE audit_log SET actor = 'mallory'", "DELETE FROM audit_log"])
def test_database_triggers_refuse_mutation(app, sql):
    _seed(1)
    with pytest.raises(DatabaseError, match="append-only"):
        with db.engine.begin() as conn:
            conn.execute(text(sql))


def test_modified_entry_detected(app):
    _seed()
    _raw("UPDATE audit_log SET details = :d WHERE id = 3", d=json.dumps({"i": 999}))
    result = audit.verify_chain()
    assert not result.ok
    assert (3, "entry_hash mismatch (entry contents modified)") in result.errors


def test_modified_entry_with_recomputed_hash_detected(app):
    """An attacker who also recomputes the edited entry's own hash still
    breaks the link from the following entry."""
    _seed()
    e = db.session.get(AuditEntry, 3)
    forged = audit.compute_entry_hash(id=3, timestamp=e.timestamp, actor="mallory", action=e.action,
                                      evidence_id=e.evidence_id, details=e.details, prev_hash=e.prev_hash)
    _raw("UPDATE audit_log SET actor = 'mallory', entry_hash = :h WHERE id = 3", h=forged)
    result = audit.verify_chain()
    assert not result.ok
    # The signature no longer matches, and the next entry's link breaks.
    assert sorted(eid for eid, _ in result.errors) == [3, 4]
    assert any("invalid signature" in msg for _, msg in result.errors)


def test_deleted_entry_detected(app):
    _seed()
    _raw("DELETE FROM audit_log WHERE id = 2")
    result = audit.verify_chain()
    assert not result.ok
    assert all(eid == 3 for eid, _ in result.errors)


def test_truncation_detected_with_external_head(app, tmp_path):
    _seed()
    head = audit.verify_chain().head_hash
    _raw("DELETE FROM audit_log WHERE id = (SELECT MAX(id) FROM audit_log)")
    assert audit.verify_chain().ok  # undetectable without an external anchor...
    assert not audit.verify_chain(expected_head=head).ok  # ...detected with one


def test_audit_page_reports_broken_chain(app, client_for):
    _seed()
    _raw("UPDATE audit_log SET actor = 'mallory' WHERE id = 2")
    resp = client_for("rita").get("/audit")
    assert b"HASH CHAIN BROKEN" in resp.data


def test_custody_actions_are_chained(app, upload, client_for):
    eid = upload()
    bob = db.session.execute(text("SELECT id FROM users WHERE username = 'bob'")).scalar()
    client_for("alice").post(f"/evidence/{eid}/transfer", data={"to_user_id": bob, "reason": "analysis"})
    client_for("rita").post(f"/evidence/{eid}/verify")
    actions = [e.action for e in audit.entries_for_evidence(eid)]
    assert actions == ["evidence.upload", "custody.transfer", "evidence.verify"]
    assert audit.verify_chain().ok


def test_certificate_pdf(app, upload, client_for):
    import hashlib

    eid = upload(b"certify me")
    resp = client_for("rita").post(f"/evidence/{eid}/certificate")
    assert resp.status_code == 200 and resp.mimetype == "application/pdf"
    text_ = "".join(p.extract_text() for p in PdfReader(io.BytesIO(resp.data)).pages)
    assert hashlib.sha256(b"certify me").hexdigest() in text_.replace("\n", "")
    assert "evidence.upload" in text_ and "INTEGRITY CHECK FAILED" not in text_
    issue = audit.entries_for_evidence(eid)[-1]
    assert issue.action == "certificate.issue"
    assert json.loads(issue.details)["pdf_sha256"] == hashlib.sha256(resp.data).hexdigest()


def test_certificate_flags_broken_chain(app, upload, client_for):
    eid = upload()
    _raw("UPDATE audit_log SET actor = 'mallory' WHERE id = 1")
    resp = client_for("rita").post(f"/evidence/{eid}/certificate")
    text_ = "".join(p.extract_text() for p in PdfReader(io.BytesIO(resp.data)).pages)
    assert "INTEGRITY CHECK FAILED" in text_

"""Ed25519-signed entries and external anchors close the gaps a bare hash
chain leaves: whole-chain rewrites and truncation of the newest entries."""

import json

from sqlalchemy import select, text

from app import audit, db
from app.models import AuditEntry
from app.signing import Signer

from .test_audit_log import _raw, _seed


def test_every_entry_is_signed(app):
    _seed()
    s = audit.signer()
    for e in db.session.execute(select(AuditEntry)).scalars():
        assert e.key_id == s.key_id
        assert s.verify(e.signature, e.entry_hash.encode())


def test_full_chain_rewrite_without_key_is_detected(app, tmp_path):
    """An attacker with database access rebuilds every hash consistently, but
    has to sign with their own key."""
    _seed()
    attacker = Signer.load_or_create(str(tmp_path / "attacker.pem"))
    entries = db.session.execute(select(AuditEntry).order_by(AuditEntry.id)).scalars().all()
    prev = audit.GENESIS_HASH
    rewrites = []
    for e in entries:
        actor = "mallory" if e.id == 3 else e.actor
        h = audit.compute_entry_hash(id=e.id, timestamp=e.timestamp, actor=actor, action=e.action,
                                     evidence_id=e.evidence_id, details=e.details, prev_hash=prev)
        rewrites.append((e.id, actor, prev, h, attacker.sign(h.encode())))
        prev = h
    with db.engine.begin() as conn:
        conn.execute(text("DROP TRIGGER IF EXISTS audit_log_no_update"))
        for eid, actor, p, h, sig in rewrites:
            conn.execute(text("UPDATE audit_log SET actor=:a, prev_hash=:p, entry_hash=:h, signature=:s WHERE id=:i"),
                         {"a": actor, "p": p, "h": h, "s": sig, "i": eid})
    db.session.expire_all()
    result = audit.verify_chain()
    assert not result.ok
    assert all("invalid signature" in msg for _, msg in result.errors)


def test_signature_must_match_server_key(app):
    _seed(2)
    _raw("UPDATE audit_log SET key_id = 'deadbeefdeadbeef' WHERE id = 1")
    assert any("unknown key" in m for _, m in audit.verify_chain().errors)


def test_anchor_detects_truncation(app):
    _seed()
    a = audit.anchor()
    assert audit.verify_chain().ok
    _raw("DELETE FROM audit_log WHERE id = :i", i=a["entry_id"])
    result = audit.verify_chain()
    assert not result.ok
    assert any("missing (log truncated)" in m for _, m in result.errors)


def test_anchor_detects_rewritten_anchored_entry(app):
    _seed()
    a = audit.anchor()
    _raw("UPDATE audit_log SET entry_hash = :h WHERE id = :i", h="f" * 64, i=a["entry_id"])
    assert any("no longer matches its anchored hash" in m for _, m in audit.verify_chain().errors)


def test_tampered_anchor_file_is_detected(app):
    _seed()
    audit.anchor()
    path = app.config["ANCHOR_FILE"]
    line = json.loads(open(path).read())
    line["entry_id"] -= 1  # try to make an earlier truncation look legitimate
    with open(path, "w") as fh:
        fh.write(json.dumps(line) + "\n")
    assert any("invalid signature (anchor file tampered)" in m for _, m in audit.verify_chain().errors)


def test_certificate_issue_writes_an_anchor(app, upload, client_for):
    eid = upload()
    client_for("rita").post(f"/evidence/{eid}/certificate")
    anchors = audit.load_anchors()
    assert len(anchors) == 1
    last = db.session.execute(select(AuditEntry).order_by(AuditEntry.id.desc())).scalars().first()
    assert anchors[0][1]["entry_id"] == last.id and last.action == "certificate.issue"


def test_key_file_is_created_once_and_reused(tmp_path):
    p = str(tmp_path / "k" / "key.pem")
    assert Signer.load_or_create(p).key_id == Signer.load_or_create(p).key_id


import io


def test_certificate_verification(app, upload, client_for):
    eid = upload()
    rita = client_for("rita")
    pdf = rita.post(f"/evidence/{eid}/certificate").data
    ok = rita.post("/certificates/verify", data={"file": (io.BytesIO(pdf), "c.pdf")},
                   content_type="multipart/form-data")
    assert b"GENUINE" in ok.data
    forged = pdf + b"\n%appended by a forger\n"  # still opens in any PDF reader
    assert forged != pdf
    bad = rita.post("/certificates/verify", data={"file": (io.BytesIO(forged), "c.pdf")},
                    content_type="multipart/form-data")
    assert b"NOT VERIFIED" in bad.data
    # carol is not on the case: told it's genuine, but not which evidence.
    other = client_for("carol").post("/certificates/verify", data={"file": (io.BytesIO(pdf), "c.pdf")},
                                     content_type="multipart/form-data")
    assert b"GENUINE" in other.data and b"not assigned" in other.data


def test_unchanged_head_is_not_reanchored(app):
    _seed(2)
    assert audit.anchor() is not None
    assert audit.anchor() is None
    _seed(1)
    assert audit.anchor() is not None
    assert len(audit.load_anchors()) == 2

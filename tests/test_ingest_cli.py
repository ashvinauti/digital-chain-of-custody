"""`flask ingest` for files too large to upload through the browser."""

import hashlib
import os

from sqlalchemy import select

from app import audit, db
from app.models import Evidence


def _ingest(app, path, *extra):
    return app.test_cli_runner().invoke(args=["ingest", str(path), "--case", "C-1", "--description", "SSD image", *extra])


def test_ingest_large_file_with_matching_hash(app, tmp_path):
    data = os.urandom(3 * 1024 * 1024 + 7)  # several hashing chunks
    path = tmp_path / "disk.dd"
    path.write_bytes(data)
    result = _ingest(app, path, "--as", "alice", "--expected-sha256", hashlib.sha256(data).hexdigest())
    assert result.exit_code == 0, result.output
    ev = db.session.execute(select(Evidence)).scalar_one()
    assert ev.sha256 == hashlib.sha256(data).hexdigest() and ev.size_bytes == len(data)
    assert '"via":"cli"' in audit.entries_for_evidence(ev.id)[0].details


def test_ingest_rejects_mismatch_and_non_members(app, tmp_path):
    path = tmp_path / "disk.dd"
    path.write_bytes(b"data")
    assert "hash mismatch" in _ingest(app, path, "--as", "alice", "--expected-sha256", "1" * 64).output
    assert "not assigned" in _ingest(app, path, "--as", "carol").output
    assert "only investigators" in _ingest(app, path, "--as", "rita").output
    assert db.session.execute(select(Evidence)).first() is None
    assert os.listdir(app.config["EVIDENCE_DIR"]) == []  # rejected file removed


def test_cli_verify_log_and_anchor(app):
    runner = app.test_cli_runner()
    assert "anchored entry" in runner.invoke(args=["anchor"]).output
    out = runner.invoke(args=["verify-log"])
    assert out.exit_code == 0 and "1 anchors" in out.output


def test_cli_verify_certificate(app, upload, client_for, tmp_path):
    eid = upload()
    pdf = tmp_path / "c.pdf"
    pdf.write_bytes(client_for("rita").post(f"/evidence/{eid}/certificate").data)
    runner = app.test_cli_runner()
    assert runner.invoke(args=["verify-certificate", str(pdf)]).output.startswith("VALID")
    pdf.write_bytes(pdf.read_bytes() + b"x")
    assert runner.invoke(args=["verify-certificate", str(pdf)]).exit_code == 1

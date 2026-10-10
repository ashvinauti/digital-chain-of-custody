"""Read-only analysis tools, findings and verified export."""

import hashlib
import io
import json
import os

import pytest
from pypdf import PdfReader
from sqlalchemy import select

from app import analysis, audit, db
from app.models import AuditEntry, Evidence
from app.services import evidence_path

from .conftest import user_id


@pytest.fixture
def sample(tmp_path):
    def make(data):
        p = tmp_path / "sample.bin"
        p.write_bytes(data)
        return str(p)
    return make


@pytest.mark.parametrize("data,expected", [
    (b"%PDF-1.7\n...", "PDF document"),
    (b"PK\x03\x04" + b"\x00" * 100, "ZIP archive"),
    (b"SQLite format 3\x00" + b"\x00" * 100, "SQLite database"),
    (b"MZ\x90\x00" + b"\x00" * 100, "Windows executable"),
    (b"\xeb\x52\x90NTFS    " + b"\x00" * 600, "NTFS volume"),
    (b"\x00" * 510 + b"\x55\xaa", "MBR partition table"),
    (b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 10, "EnCase"),
    (b"plain old text\n" * 20, "Text"),
])
def test_identify(sample, data, expected):
    assert expected in analysis.identify(sample(data))["type"]


def test_profile_hashes_and_entropy(sample):
    data = os.urandom(300_000)
    r = analysis.profile(sample(data))
    assert r["md5"] == hashlib.md5(data).hexdigest()
    assert r["sha1"] == hashlib.sha1(data).hexdigest()
    assert r["sha256"] == hashlib.sha256(data).hexdigest()
    assert r["entropy_bits_per_byte"] > 7.9
    assert analysis.profile(sample(b"\x00" * 10000))["entropy_bits_per_byte"] == 0


def test_hexdump(sample):
    r = analysis.hexdump(sample(bytes(range(64))), offset=16, length=16)
    assert r["rows"] == [{"offset": 16, "hex": " ".join(f"{b:02x}" for b in range(16, 32)),
                          "ascii": "................"}]


def test_strings_ascii_and_utf16(sample):
    data = b"\x00\x01hello world\x00\xff" + "secret".encode("utf-16-le") + b"\x00\x00ab\x00"
    path = sample(data)
    assert [(s["offset"], s["text"]) for s in analysis.extract_strings(path, "ascii", 5)["strings"]] == [(2, "hello world")]
    assert [s["text"] for s in analysis.extract_strings(path, "utf16le", 5)["strings"]] == ["secret"]


def test_strings_and_search_across_chunk_boundaries(sample, monkeypatch):
    monkeypatch.setattr(analysis, "CHUNK", 64)
    data = b"\x00" * 60 + b"BOUNDARYSTRING" + b"\x00" * 100 + "Password".encode("utf-16-le") + b"\x00" * 50
    path = sample(data)
    found = analysis.extract_strings(path, "ascii", 6)["strings"]
    assert found == [{"offset": 60, "text": "BOUNDARYSTRING"}]
    hits = analysis.search(path, "boundary")["hits"]  # case-insensitive
    assert [(h["offset"], h["encoding"]) for h in hits] == [(60, "ascii")]
    hits = analysis.search(path, "PASSWORD")["hits"]
    assert [(h["offset"], h["encoding"]) for h in hits] == [(174, "utf16le")]


def test_strings_pagination(sample):
    path = sample(b"\x00".join(b"string%03d" % i for i in range(50)))
    first = analysis.extract_strings(path, "ascii", 6, limit=20)
    second = analysis.extract_strings(path, "ascii", 6, limit=20, start=first["next_offset"])
    assert [s["text"] for s in first["strings"] + second["strings"]] == [f"string{i:03d}" for i in range(40)]


def test_analysis_never_modifies_the_original(app, upload, client_for):
    eid = upload(b"%PDF-1.4 important evidence")
    ev = db.session.get(Evidence, eid)
    before = (os.stat(evidence_path(ev)).st_mtime_ns, ev.sha256)
    alice = client_for("alice")
    for tool, extra in [("identify", {}), ("profile", {}), ("hex", {"offset": 0}),
                        ("strings", {}), ("search", {"keyword": "evidence"})]:
        assert alice.post(f"/evidence/{eid}/analysis", data={"tool": tool, **extra}).status_code == 200
    from app.services import check_evidence_integrity
    assert check_evidence_integrity(ev)[0]
    assert os.stat(evidence_path(ev)).st_mtime_ns == before[0]
    runs = [json.loads(e.details)["tool"] for e in audit.entries_for_evidence(eid) if e.action == "analysis.run"]
    assert runs == ["identify", "profile", "hex", "strings", "search"]


def test_reviewer_cannot_run_tools(upload, client_for):
    eid = upload()
    assert client_for("rita").post(f"/evidence/{eid}/analysis", data={"tool": "identify"}).status_code == 403


def test_findings_go_into_chain_and_certificate(upload, client_for):
    eid = upload()
    client_for("alice").post(f"/evidence/{eid}/notes", data={"text": "Deleted chat fragment at offset 0x1F400"})
    note = [e for e in audit.entries_for_evidence(eid) if e.action == "analysis.note"]
    assert json.loads(note[0].details)["text"].startswith("Deleted chat")
    assert audit.verify_chain().ok
    pdf = client_for("rita").post(f"/evidence/{eid}/certificate").data
    text_ = "".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf)).pages)
    assert "Deleted chat fragment" in text_


def test_export_by_custodian_returns_identical_bytes(upload, client_for):
    data = os.urandom(5000)
    eid = upload(data)
    resp = client_for("alice").post(f"/evidence/{eid}/export")
    assert resp.status_code == 200 and resp.data == data
    assert audit.entries_for_evidence(eid)[-1].action == "evidence.export"


def test_export_refused_for_non_custodian(upload, client_for):
    eid = upload()
    resp = client_for("bob").post(f"/evidence/{eid}/export")
    assert resp.status_code == 302
    assert all(e.action != "evidence.export" for e in audit.entries_for_evidence(eid))


def test_export_refused_when_file_tampered(upload, client_for):
    eid = upload(b"original")
    path = evidence_path(db.session.get(Evidence, eid))
    os.chmod(path, 0o600)
    with open(path, "wb") as fh:
        fh.write(b"tampered")
    resp = client_for("alice").post(f"/evidence/{eid}/export")
    assert resp.status_code == 302
    assert audit.entries_for_evidence(eid)[-1].action == "evidence.export_refused"


def test_upload_with_expected_hash(upload, client_for):
    data = b"acquired image"
    good = hashlib.sha256(data).hexdigest()
    eid = upload(data, expected_sha256=good)
    assert json.loads(audit.entries_for_evidence(eid)[0].details)["acquisition_hash_matched"] is True
    resp = client_for("alice").post(
        "/evidence/new",
        data={"case_id": 1, "description": "x", "expected_sha256": "0" * 64, "file": (io.BytesIO(data), "x.dd")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400 and b"hash mismatch" in resp.data
    assert db.session.execute(select(Evidence)).scalars().all().__len__() == 1
    last = db.session.execute(select(AuditEntry).order_by(AuditEntry.id.desc())).scalars().first()
    assert last.action == "evidence.ingest_rejected"


@pytest.mark.parametrize("seed", range(5))
def test_results_do_not_depend_on_chunk_size(sample, monkeypatch, seed):
    import random

    rnd = random.Random(seed)
    parts = []
    for _ in range(200):
        word = "".join(rnd.choice("abcdefXYZ0123 ") for _ in range(rnd.randint(1, 30)))
        parts.append(rnd.choice([word.encode(), word.encode("utf-16-le"), bytes(rnd.randint(0, 255) for _ in range(rnd.randint(0, 9)))]))
    path = sample(b"".join(parts) + b"needle" + "NEEDLE".encode("utf-16-le"))

    def run():
        return (analysis.extract_strings(path, "ascii", 4, limit=2000),
                analysis.extract_strings(path, "utf16le", 4, limit=2000),
                analysis.search(path, "needle", max_hits=1000))

    monkeypatch.setattr(analysis, "CHUNK", 1024 * 1024)
    expected = run()
    for size in (7, 13, 64, 257):
        monkeypatch.setattr(analysis, "CHUNK", size)
        assert run() == expected, size

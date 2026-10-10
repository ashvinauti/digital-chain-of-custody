import hashlib
import io
import os
import stat

import pytest

from app import db
from app.hashing import CHUNK_SIZE, sha256_file, sha256_stream, store_and_hash
from app.models import Evidence
from app.services import check_evidence_integrity, evidence_path

# Published SHA-256 test vectors (FIPS 180-2).
VECTORS = {
    b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
}


@pytest.mark.parametrize("data,expected", VECTORS.items())
def test_sha256_known_vectors(data, expected):
    assert sha256_stream(io.BytesIO(data)) == expected


def test_multi_chunk_stream_matches_hashlib():
    data = os.urandom(CHUNK_SIZE * 2 + 123)
    assert sha256_stream(io.BytesIO(data)) == hashlib.sha256(data).hexdigest()


def test_store_and_hash_writes_exact_bytes_read_only(tmp_path):
    data = os.urandom(5000)
    dest = tmp_path / "item"
    digest, size = store_and_hash(io.BytesIO(data), dest)
    assert (digest, size) == (hashlib.sha256(data).hexdigest(), len(data))
    assert dest.read_bytes() == data
    assert sha256_file(dest) == digest
    assert not os.stat(dest).st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)


def test_store_and_hash_refuses_to_overwrite(tmp_path):
    dest = tmp_path / "item"
    dest.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        store_and_hash(io.BytesIO(b"new"), dest)


def test_upload_stores_sha256_on_record_and_in_log(app, upload):
    content = b"evidence content \x00\x01"
    ev = db.session.get(Evidence, upload(content))
    assert ev.sha256 == hashlib.sha256(content).hexdigest()
    assert ev.size_bytes == len(content)
    match, actual = check_evidence_integrity(ev)
    assert match and actual == ev.sha256


def test_tampered_file_detected(app, upload, client_for):
    ev = db.session.get(Evidence, upload(b"original"))
    path = evidence_path(ev)
    os.chmod(path, 0o600)
    with open(path, "wb") as fh:
        fh.write(b"tampered")
    resp = client_for("rita").post(f"/evidence/{ev.id}/verify", follow_redirects=True)
    assert b"HASH MISMATCH" in resp.data
    assert check_evidence_integrity(ev)[0] is False


def test_altered_hash_column_detected(app, upload):
    """Rewriting both the file and the evidence.sha256 column is still caught,
    because the acquisition hash is also in the hash-chained log."""
    ev = db.session.get(Evidence, upload(b"original"))
    path = evidence_path(ev)
    os.chmod(path, 0o600)
    with open(path, "wb") as fh:
        fh.write(b"forged")
    ev.sha256 = hashlib.sha256(b"forged").hexdigest()
    db.session.commit()
    assert check_evidence_integrity(ev)[0] is False


def test_missing_file_detected(app, upload):
    ev = db.session.get(Evidence, upload())
    os.remove(evidence_path(ev))
    assert check_evidence_integrity(ev) == (False, None)

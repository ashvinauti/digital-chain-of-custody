"""JSON API: token auth, same permissions and case scoping as the UI."""

import hashlib
import io

import pytest

from app import audit, services
from app.models import ApiToken


@pytest.fixture
def token_for(app):
    def make(username):
        return {"Authorization": "Bearer " + services.create_api_token(services.get_user(username), "test")}
    return make


@pytest.fixture
def api(app):
    return app.test_client()


def _upload(api, headers, data=b"api evidence", **extra):
    return api.post("/api/v1/evidence", headers=headers, content_type="multipart/form-data",
                    data={"case": "C-1", "description": "via api", "file": (io.BytesIO(data), "a.bin"), **extra})


def test_requires_token(api):
    assert api.get("/api/v1/me").status_code == 401
    assert api.get("/api/v1/me", headers={"Authorization": "Bearer coc_nope"}).status_code == 401


def test_session_cookie_alone_is_not_accepted(client_for):
    """Otherwise CSRF-exempt API routes would be forgeable from another site."""
    browser = client_for("alice")
    assert browser.get("/api/v1/me").status_code == 401
    assert browser.post("/api/v1/evidence/1/verify").status_code == 401


def test_token_identifies_user_even_with_other_session(client_for, token_for):
    browser = client_for("rita")  # session for rita...
    resp = browser.get("/api/v1/me", headers=token_for("alice"))  # ...token for alice
    assert resp.json == {"username": "alice", "role": "investigator"}


def test_revoked_token_rejected(app, api):
    alice = services.get_user("alice")
    token = services.create_api_token(alice, "t")
    tok_id = ApiToken.query.one().id
    services.revoke_api_token(alice, tok_id)
    assert api.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_upload_verify_transfer_flow(api, token_for):
    alice = token_for("alice")
    data = b"api evidence"
    resp = _upload(api, alice, data, expected_sha256=hashlib.sha256(data).hexdigest())
    assert resp.status_code == 201, resp.json
    ev = resp.json
    assert ev["sha256"] == hashlib.sha256(data).hexdigest()
    assert api.post(f"/api/v1/evidence/{ev['id']}/verify", headers=token_for("rita")).json["match"] is True
    resp = api.post(f"/api/v1/evidence/{ev['id']}/transfer", headers=alice, json={"to": "bob", "reason": "lab"})
    assert resp.status_code == 200 and resp.json["custodian"] == "bob"
    events = api.get(f"/api/v1/evidence/{ev['id']}", headers=alice).json["events"]
    assert [e["action"] for e in events] == ["evidence.upload", "evidence.verify", "custody.transfer"]
    assert [e["details"] for e in events][0].find('"via":"api"') > 0


def test_upload_hash_mismatch_rejected(api, token_for):
    resp = _upload(api, token_for("alice"), expected_sha256="0" * 64)
    assert resp.status_code == 409 and "hash mismatch" in resp.json["error"]


def test_api_enforces_roles_and_cases(api, token_for):
    eid = _upload(api, token_for("alice")).json["id"]
    assert _upload(api, token_for("rita")).status_code == 403  # reviewer can't upload
    assert api.get(f"/api/v1/evidence/{eid}", headers=token_for("carol")).status_code == 404  # not on case
    assert api.get("/api/v1/evidence", headers=token_for("carol")).json == []
    assert api.get("/api/v1/evidence", headers=token_for("adam")).status_code == 403  # admin
    assert api.get("/api/v1/audit/verify", headers=token_for("adam")).json["ok"] is True


def test_api_analysis_notes_export_certificate(api, token_for):
    alice = token_for("alice")
    data = b"%PDF-1.4 hello secret world"
    eid = _upload(api, alice, data).json["id"]
    assert api.post(f"/api/v1/evidence/{eid}/analysis/identify", headers=alice).json["type"] == "PDF document"
    hits = api.post(f"/api/v1/evidence/{eid}/analysis/search", headers=alice, json={"keyword": "SECRET"}).json["hits"]
    assert hits[0]["offset"] == data.index(b"secret")
    assert api.post(f"/api/v1/evidence/{eid}/analysis/bogus", headers=alice).status_code == 400
    assert api.post(f"/api/v1/evidence/{eid}/notes", headers=alice, json={"text": "found it"}).status_code == 201
    exp = api.post(f"/api/v1/evidence/{eid}/export", headers=alice)
    assert exp.data == data and exp.headers["X-Evidence-SHA256"] == hashlib.sha256(data).hexdigest()
    pdf = api.post(f"/api/v1/evidence/{eid}/certificate", headers=token_for("rita")).data
    check = api.post("/api/v1/certificates/verify", headers=token_for("rita"), data=pdf)
    assert check.json["valid"] is True and check.json["evidence_id"] == eid
    assert audit.verify_chain().ok

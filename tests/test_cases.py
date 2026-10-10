"""Case-level access: users only see evidence in cases they are assigned to."""

import io

import pytest

from app import db, services
from app.models import AuditEntry, Evidence
from sqlalchemy import select

from .conftest import user_id


@pytest.fixture
def ev1(upload):
    return upload()


@pytest.mark.parametrize("method,url", [
    ("GET", "/evidence/{id}"),
    ("POST", "/evidence/{id}/verify"),
    ("POST", "/evidence/{id}/certificate"),
    ("GET", "/evidence/{id}/analysis"),
    ("POST", "/evidence/{id}/notes"),
    ("POST", "/evidence/{id}/export"),
    ("POST", "/evidence/{id}/transfer"),
])
def test_non_member_gets_404(ev1, client_for, method, url):
    """carol is an investigator, but not on case C-1. A 404 (not 403) means
    she cannot even confirm the item exists."""
    resp = client_for("carol").open(url.format(id=ev1), method=method, data={"text": "x"})
    assert resp.status_code == 404


def test_lists_only_show_own_cases(ev1, client_for):
    assert b"img.dd" in client_for("alice").get("/evidence").data
    carol = client_for("carol")
    assert b"img.dd" not in carol.get("/evidence").data
    assert b"C-1" not in carol.get("/cases").data
    assert carol.get("/cases/1").status_code == 404


def test_cannot_upload_into_someone_elses_case(client_for):
    resp = client_for("carol").post(
        "/evidence/new",
        data={"case_id": 1, "description": "x", "file": (io.BytesIO(b"x"), "x.bin")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    assert db.session.execute(select(Evidence)).first() is None


def test_custody_only_transfers_within_case(ev1, client_for):
    client_for("alice").post(f"/evidence/{ev1}/transfer", data={"to_user_id": user_id("carol"), "reason": "x"})
    db.session.expire_all()
    assert db.session.get(Evidence, ev1).custodian.username == "alice"


def test_admin_manages_membership_but_never_sees_evidence(ev1, client_for):
    adam = client_for("adam")
    assert adam.get(f"/evidence/{ev1}").status_code == 403
    adam.post("/admin/cases/1", data={"op": "add", "user_id": user_id("carol")})
    carol = client_for("carol")
    assert carol.get(f"/evidence/{ev1}").status_code == 200
    adam.post("/admin/cases/1", data={"op": "remove", "user_id": user_id("carol")})
    assert carol.get(f"/evidence/{ev1}").status_code == 404
    actions = [e.action for e in db.session.execute(select(AuditEntry)).scalars()]
    assert "case.member_add" in actions and "case.member_remove" in actions


def test_custodian_cannot_be_removed_from_case(ev1, client_for):
    client_for("adam").post("/admin/cases/1", data={"op": "remove", "user_id": user_id("alice")})
    case = services.get_case_for(services.get_user("adam"), 1)
    assert case.has_member(services.get_user("alice"))


def test_admin_cannot_add_admin_to_case(client_for):
    client_for("adam").post("/admin/cases/1", data={"op": "add", "user_id": user_id("adam")})
    case = services.get_case_for(services.get_user("adam"), 1)
    assert not case.has_member(services.get_user("adam"))


def test_v1_database_is_refused(tmp_path):
    import sqlite3

    from app import create_app

    path = tmp_path / "v1.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, case_number TEXT)")
    con.commit()
    con.close()
    with pytest.raises(RuntimeError, match="created by v1"):
        create_app({"SECRET_KEY": "x", "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}",
                    "EVIDENCE_DIR": str(tmp_path / "e"), "SIGNING_KEY_PATH": str(tmp_path / "k.pem"),
                    "ANCHOR_FILE": str(tmp_path / "a.jsonl")})

import json

import pytest
from sqlalchemy import select

from app import db
from app.auth import PERMISSIONS
from app.models import AuditEntry, Evidence, User

# (method, url, permission). Evidence #1 (case C-1, custodian alice) and
# user #2 (bob) exist in every test.
ROUTES = [
    ("GET", "/cases", "cases.view"),
    ("GET", "/cases/1", "cases.view"),
    ("GET", "/evidence", "evidence.view"),
    ("GET", "/evidence/1", "evidence.view"),
    ("GET", "/evidence/new", "evidence.create"),
    ("POST", "/evidence/1/transfer", "evidence.transfer"),
    ("POST", "/evidence/1/verify", "evidence.verify"),
    ("GET", "/evidence/1/analysis", "evidence.analyze"),
    ("POST", "/evidence/1/notes", "evidence.analyze"),
    ("POST", "/evidence/1/export", "evidence.export"),
    ("POST", "/evidence/1/certificate", "certificate.issue"),
    ("GET", "/certificates/verify", "certificate.verify"),
    ("GET", "/audit", "audit.view"),
    ("GET", "/admin/cases", "cases.manage"),
    ("GET", "/admin/cases/1", "cases.manage"),
    ("GET", "/admin/users", "users.manage"),
    ("POST", "/admin/users/2/active", "users.manage"),
    ("GET", "/account/", "account.self"),
]
USERS = {"investigator": "alice", "reviewer": "rita", "admin": "adam"}


@pytest.fixture
def evidence(upload):
    assert upload() == 1


@pytest.mark.parametrize("role", USERS)
@pytest.mark.parametrize("method,url,permission", ROUTES)
def test_role_matrix(evidence, client_for, role, method, url, permission):
    client = client_for(USERS[role])
    resp = client.open(url, method=method, data={"active": "1", "text": "note"})
    if role in PERMISSIONS[permission]:
        assert resp.status_code in (200, 302), resp.status_code
    else:
        assert resp.status_code == 403


@pytest.mark.parametrize("method,url,_", ROUTES)
def test_anonymous_redirected_to_login(evidence, app, method, url, _):
    resp = app.test_client().open(url, method=method)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_every_route_declares_a_permission(app):
    """Guards against a new route being added without @require(...)."""
    public = {"static", "auth.login", "auth.login_2fa", "auth.logout", "main.index", "main.public_key"}
    for rule in app.url_map.iter_rules():
        if rule.endpoint in public:
            continue
        view = app.view_functions[rule.endpoint]
        assert getattr(view, "required_permission", None) in PERMISSIONS, rule.rule
    tested = {p for _, _, p in ROUTES}
    assert tested == set(PERMISSIONS), "every permission should be exercised by ROUTES"


def test_denied_access_is_audited(client_for):
    client_for("rita").get("/admin/users")
    last = db.session.execute(select(AuditEntry).order_by(AuditEntry.id.desc())).scalars().first()
    assert last.action == "access.denied" and last.actor == "rita"
    assert json.loads(last.details)["permission"] == "users.manage"


def test_wrong_password_and_disabled_user_cannot_log_in(app, client_for):
    client = app.test_client()
    assert client.post("/login", data={"username": "alice", "password": "nope"}).status_code == 401
    bob = db.session.execute(select(User).where(User.username == "bob")).scalar_one()
    client_for("adam").post(f"/admin/users/{bob.id}/active", data={"active": "0"})
    resp = client.post("/login", data={"username": "bob", "password": "correct-horse-battery"})
    assert resp.status_code == 401  # re-rendered form, not a redirect


def _user(name):
    return db.session.execute(select(User).where(User.username == name)).scalar_one()


def test_only_current_custodian_can_transfer(evidence, client_for):
    bob, alice = _user("bob"), _user("alice")
    client_for("bob").post("/evidence/1/transfer", data={"to_user_id": bob.id, "reason": "grab"})
    db.session.expire_all()
    assert db.session.get(Evidence, 1).custodian_id == alice.id

    client_for("alice").post("/evidence/1/transfer", data={"to_user_id": bob.id, "reason": "lab analysis"})
    db.session.expire_all()
    assert db.session.get(Evidence, 1).custodian_id == bob.id


def test_custody_cannot_go_to_non_investigator(evidence, client_for):
    rita = _user("rita")
    client_for("alice").post("/evidence/1/transfer", data={"to_user_id": rita.id, "reason": "x"})
    db.session.expire_all()
    assert db.session.get(Evidence, 1).custodian_id == _user("alice").id


def test_csrf_enforced_when_enabled(app, client_for):
    client = client_for("alice")
    app.config["WTF_CSRF_ENABLED"] = True
    resp = client.post("/evidence/new", data={"case_number": "x"})
    assert resp.status_code == 400

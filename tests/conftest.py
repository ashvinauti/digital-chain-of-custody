import functools
import io

import pytest
from flask import g
from werkzeug import security

import app.models
from app import create_app, db
from app.services import add_case_member, create_case, create_user, get_user

PASSWORD = "correct-horse-battery"

# scrypt is deliberately slow; tests don't need that.
app.models.generate_password_hash = functools.partial(security.generate_password_hash, method="pbkdf2:sha256:1000")

# Case C-1: alice, bob (investigators), rita (reviewer). Case C-2: carol only.
USERS = [("alice", "investigator"), ("bob", "investigator"), ("rita", "reviewer"),
         ("carol", "investigator"), ("adam", "admin")]


@pytest.fixture
def app(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'test.db'}",
            "EVIDENCE_DIR": str(tmp_path / "evidence"),
            "SIGNING_KEY_PATH": str(tmp_path / "keys" / "signing_key.pem"),
            "ANCHOR_FILE": str(tmp_path / "anchors" / "anchors.jsonl"),
            "WTF_CSRF_ENABLED": False,
        }
    )

    # Tests hold an app context open so they can use db.session directly.
    # Flask then reuses that context (and its `g`) for test-client requests,
    # so clear Flask-Login's cached user to keep clients from sharing a login.
    @app.before_request
    def _fresh_login_state():
        g.pop("_login_user", None)

    with app.app_context():
        for name, role in USERS:
            create_user(name, PASSWORD, role, actor=None)
        c1 = create_case("C-1", "Laptop seizure", actor=None)
        c2 = create_case("C-2", "Unrelated fraud case", actor=None)
        for name in ("alice", "bob", "rita"):
            add_case_member(c1, get_user(name), actor=None)
        add_case_member(c2, get_user("carol"), actor=None)
        yield app
        db.session.remove()
        db.engine.dispose()


def login(app, username, password=PASSWORD):
    client = app.test_client()
    resp = client.post("/login", data={"username": username, "password": password})
    return client, resp


@pytest.fixture
def client_for(app):
    """client_for("alice") -> a test client logged in as alice."""

    def make(username):
        client, resp = login(app, username)
        assert resp.status_code == 302, f"login failed for {username}"
        return client

    return make


@pytest.fixture
def upload(client_for):
    """Upload `content` into case C-1 as alice; returns the new evidence id."""

    def do(content=b"disk image bytes", client=None, filename="img.dd", **extra):
        client = client or client_for("alice")
        resp = client.post(
            "/evidence/new",
            data={"case_id": 1, "description": "laptop", "file": (io.BytesIO(content), filename), **extra},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 302, resp.data
        return int(resp.headers["Location"].rstrip("/").split("/")[-1])

    return do


def user_id(name):
    return get_user(name).id

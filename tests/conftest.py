import io

import pytest
from flask import g

from app import create_app, db
from app.services import create_user

PASSWORD = "correct-horse-battery"


@pytest.fixture
def app(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'test.db'}",
            "EVIDENCE_DIR": str(tmp_path / "evidence"),
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
        for name, role in [("alice", "investigator"), ("bob", "investigator"), ("rita", "reviewer"), ("adam", "admin")]:
            create_user(name, PASSWORD, role, actor=None)
        yield app
        db.session.remove()
        db.engine.dispose()


@pytest.fixture
def client_for(app):
    """client_for("alice") -> a test client logged in as alice."""

    def make(username):
        client = app.test_client()
        resp = client.post("/login", data={"username": username, "password": PASSWORD})
        assert resp.status_code == 302, f"login failed for {username}"
        return client

    return make


@pytest.fixture
def upload(client_for):
    """Upload `content` as alice; returns the new evidence id."""

    def do(content=b"disk image bytes", client=None):
        client = client or client_for("alice")
        resp = client.post(
            "/evidence/new",
            data={"case_number": "C-1", "description": "laptop", "file": (io.BytesIO(content), "img.dd")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 302, resp.data
        return int(resp.headers["Location"].rstrip("/").split("/")[-1])

    return do

"""Lockout, two-factor authentication, forced password change, sessions."""

import pyotp
import pytest
from sqlalchemy import select

from app import db, services
from app.models import ApiToken, utcnow

from .conftest import PASSWORD, login


def _user(name):
    db.session.expire_all()
    return services.get_user(name)


def test_lockout_after_repeated_failures(app):
    limit = app.config["MAX_FAILED_LOGINS"]
    for _ in range(limit):
        assert login(app, "alice", "wrong-password")[1].status_code == 401
    assert _user("alice").is_locked
    # Even the right password is refused while locked.
    assert login(app, "alice")[1].status_code == 401


def test_success_resets_failure_count(app):
    for _ in range(app.config["MAX_FAILED_LOGINS"] - 1):
        login(app, "alice", "wrong-password")
    assert login(app, "alice")[1].status_code == 302
    assert _user("alice").failed_logins == 0


def test_admin_unlock(app, client_for):
    for _ in range(app.config["MAX_FAILED_LOGINS"]):
        login(app, "alice", "wrong-password")
    client_for("adam").post(f"/admin/users/{_user('alice').id}/unlock")
    assert login(app, "alice")[1].status_code == 302


def _enable_2fa(client):
    page = client.get("/account/2fa").data.decode()
    secret = page.split("Enter this key manually: <code>")[1].split("<")[0]
    resp = client.post("/account/2fa", data={"code": pyotp.TOTP(secret).now()})
    assert resp.status_code == 302, page
    return secret


def test_totp_enrolment_and_login(app, client_for):
    secret = _enable_2fa(client_for("alice"))
    assert _user("alice").totp_enabled

    client, resp = login(app, "alice")
    assert resp.headers["Location"].endswith("/login/2fa")
    assert client.get("/cases").status_code == 302  # not signed in yet

    # Enrolment consumed the current time step, so use the next one.
    code = pyotp.TOTP(secret).at(utcnow().timestamp() + 30)
    assert client.post("/login/2fa", data={"code": code}).status_code == 302
    assert client.get("/cases").status_code == 200


def test_totp_rejects_wrong_and_replayed_codes(app, client_for):
    secret = _enable_2fa(client_for("alice"))
    client, _ = login(app, "alice")
    assert client.post("/login/2fa", data={"code": "000000"}).status_code == 401
    code = pyotp.TOTP(secret).at(utcnow().timestamp() + 30)
    assert client.post("/login/2fa", data={"code": code}).status_code == 302
    # Same code again in a fresh sign-in: replay.
    client2, _ = login(app, "alice")
    assert client2.post("/login/2fa", data={"code": code}).status_code == 401


def test_2fa_step_cannot_be_skipped(app, client_for):
    _enable_2fa(client_for("alice"))
    client, _ = login(app, "alice")
    assert client.get("/evidence").status_code == 302
    assert "/login" in client.get("/evidence").headers["Location"]


def test_admin_created_user_must_change_password(app, client_for):
    client_for("adam").post("/admin/users", data={"username": "dave", "password": "temporary-pass-1", "role": "reviewer"})
    client, resp = login(app, "dave", "temporary-pass-1")
    assert resp.status_code == 302
    page = client.get("/cases")
    assert page.status_code == 302 and page.headers["Location"].endswith("/account/password")
    client.post("/account/password", data={"current_password": "temporary-pass-1",
                                           "new_password": "dave-chosen-pass", "confirm_password": "dave-chosen-pass"})
    assert client.get("/cases").status_code == 200


def test_require_2fa_setting_forces_enrolment(app, client_for):
    app.config["REQUIRE_2FA"] = True
    resp = client_for("alice").get("/cases")
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/account/2fa")


def test_admin_password_reset_revokes_tokens(app, client_for):
    alice = _user("alice")
    services.create_api_token(alice, "laptop")
    client_for("adam").post(f"/admin/users/{alice.id}/reset-password", data={"password": "temporary-pass-2"})
    db.session.expire_all()
    assert all(t.revoked for t in db.session.execute(select(ApiToken)).scalars())
    assert _user("alice").must_change_password
    assert login(app, "alice")[1].status_code == 401  # old password gone


@pytest.mark.parametrize("bad", ["short", ""])
def test_password_policy(client_for, bad):
    client = client_for("alice")
    resp = client.post("/account/password", data={"current_password": PASSWORD, "new_password": bad, "confirm_password": bad})
    assert resp.status_code == 400

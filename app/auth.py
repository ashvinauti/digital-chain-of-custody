"""Authentication and role-based access control.

Every route outside the login flow is wrapped in `@require(<permission>)`.
PERMISSIONS is the single source of truth for which role may do what; the
tests walk this table against every route. Case membership is checked on
top of the role, in services.get_evidence_for / get_case_for.
"""

import time
from functools import wraps

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from . import audit, db, services
from .models import User

ALL_ROLES = {"investigator", "reviewer", "admin"}

PERMISSIONS = {
    "evidence.view": {"investigator", "reviewer"},
    "evidence.create": {"investigator"},
    "evidence.transfer": {"investigator"},
    "evidence.verify": {"investigator", "reviewer"},
    "evidence.analyze": {"investigator"},
    "evidence.export": {"investigator"},
    "certificate.issue": {"investigator", "reviewer"},
    "certificate.verify": {"investigator", "reviewer"},
    "cases.view": {"investigator", "reviewer"},
    "cases.manage": {"admin"},
    "audit.view": {"reviewer", "admin"},
    "users.manage": {"admin"},
    "account.self": ALL_ROLES,
}

PENDING_2FA_SECONDS = 300


def can(user, permission):
    return user.is_authenticated and user.role in PERMISSIONS[permission]


def deny(permission):
    audit.append(
        "access.denied",
        current_user.username,
        details={"permission": permission, "path": request.path, "method": request.method},
    )
    db.session.commit()
    abort(403)


def require(permission):
    if permission not in PERMISSIONS:
        raise KeyError(f"unknown permission {permission}")

    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if not can(current_user, permission):
                deny(permission)
            return view(*args, **kwargs)

        wrapped.required_permission = permission
        return wrapped

    return decorator


bp = Blueprint("auth", __name__)

# Endpoints a signed-in user may reach before finishing required setup.
_SETUP_ENDPOINTS = {"auth.logout", "account.password", "account.two_factor", "static"}


@bp.before_app_request
def enforce_account_setup():
    """Force a password change after an admin reset, and 2FA enrolment when
    REQUIRE_2FA is on, before anything else is reachable."""
    if not current_user.is_authenticated or request.blueprint == "api" or request.endpoint in _SETUP_ENDPOINTS:
        return None
    if current_user.must_change_password:
        flash("You must set a new password before continuing.")
        return redirect(url_for("account.password"))
    if current_app.config["REQUIRE_2FA"] and not current_user.totp_enabled:
        flash("Two-factor authentication is required. Set it up to continue.")
        return redirect(url_for("account.two_factor"))
    return None


GENERIC_FAILURE = "Sign-in failed. Repeated failures lock the account temporarily."


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = services.get_user(username)
        ip = request.remote_addr
        if user is not None and user.is_locked:
            # Don't even check the password while locked.
            services.record_failed_login(None, username, ip, "locked")
            flash(GENERIC_FAILURE)
            return render_template("login.html"), 401
        if user is None or not user.active or not user.check_password(password):
            services.record_failed_login(user if user and user.active else None, username, ip, "bad_password")
            flash(GENERIC_FAILURE)
            return render_template("login.html"), 401
        session.clear()  # no state carried across the authentication boundary
        if user.totp_enabled:
            session["pending_2fa"] = {"user_id": user.id, "at": time.time()}
            return redirect(url_for("auth.login_2fa"))
        login_user(user)
        services.record_login(user, ip, "password")
        return redirect(url_for("main.index"))
    return render_template("login.html")


@bp.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    pending = session.get("pending_2fa")
    if not pending or time.time() - pending["at"] > PENDING_2FA_SECONDS:
        session.pop("pending_2fa", None)
        flash("Please sign in again.")
        return redirect(url_for("auth.login"))
    user = db.session.get(User, pending["user_id"])
    if request.method == "POST":
        ip = request.remote_addr
        if user is None or not user.active or user.is_locked:
            session.pop("pending_2fa", None)
            flash(GENERIC_FAILURE)
            return redirect(url_for("auth.login"))
        if not services.verify_totp(user, request.form.get("code")):
            services.record_failed_login(user, user.username, ip, "bad_totp")
            flash("Invalid or already-used code.")
            return render_template("login_2fa.html"), 401
        session.pop("pending_2fa", None)
        login_user(user)
        services.record_login(user, ip, "password+totp")
        return redirect(url_for("main.index"))
    return render_template("login_2fa.html")


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit.append("auth.logout", current_user.username)
    db.session.commit()
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))

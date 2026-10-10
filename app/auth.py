"""Authentication and role-based access control.

Every route outside this module's login/logout is wrapped in
`@require(<permission>)`. PERMISSIONS is the single source of truth for
which role may do what; the tests walk this table against every route.
"""

from functools import wraps

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import select

from . import audit, db
from .models import User

PERMISSIONS = {
    "evidence.view": {"investigator", "reviewer"},
    "evidence.create": {"investigator"},
    "evidence.transfer": {"investigator"},
    "evidence.verify": {"investigator", "reviewer"},
    "certificate.issue": {"investigator", "reviewer"},
    "audit.view": {"reviewer", "admin"},
    "users.manage": {"admin"},
}


def can(user, permission):
    return user.is_authenticated and user.role in PERMISSIONS[permission]


def require(permission):
    if permission not in PERMISSIONS:
        raise KeyError(f"unknown permission {permission}")

    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if not can(current_user, permission):
                audit.append(
                    "access.denied",
                    current_user.username,
                    details={"permission": permission, "path": request.path, "method": request.method},
                )
                db.session.commit()
                abort(403)
            return view(*args, **kwargs)

        wrapped.required_permission = permission
        return wrapped

    return decorator


bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = db.session.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if user and user.active and user.check_password(password):
            login_user(user)
            audit.append("auth.login", user.username, details={"ip": request.remote_addr})
            db.session.commit()
            return redirect(url_for("main.index"))
        audit.append("auth.login_failed", username[:64] or "-", details={"ip": request.remote_addr})
        db.session.commit()
        flash("Invalid credentials")
    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit.append("auth.logout", current_user.username)
    db.session.commit()
    logout_user()
    return redirect(url_for("auth.login"))

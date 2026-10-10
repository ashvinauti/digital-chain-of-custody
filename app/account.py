"""Self-service account pages: password, two-factor auth, API tokens."""

import pyotp
import segno
from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for
from flask_login import current_user
from sqlalchemy import select

from . import db, services
from .auth import require
from .models import ApiToken

bp = Blueprint("account", __name__, url_prefix="/account")


def _render_overview(new_token=None):
    tokens = db.session.execute(
        select(ApiToken).where(ApiToken.user_id == current_user.id).order_by(ApiToken.id.desc())
    ).scalars().all()
    return render_template("account.html", tokens=tokens, new_token=new_token)


@bp.route("/")
@require("account.self")
def overview():
    return _render_overview()


@bp.route("/password", methods=["GET", "POST"])
@require("account.self")
def password():
    if request.method == "POST":
        new = request.form.get("new_password", "")
        if new != request.form.get("confirm_password", ""):
            flash("New passwords do not match")
            return render_template("account_password.html"), 400
        try:
            services.change_own_password(current_user, request.form.get("current_password", ""), new)
        except ValueError as exc:
            flash(str(exc))
            return render_template("account_password.html"), 400
        flash("Password changed")
        return redirect(url_for("main.index"))
    return render_template("account_password.html")


@bp.route("/2fa", methods=["GET", "POST"])
@require("account.self")
def two_factor():
    if current_user.totp_enabled:
        if request.method == "POST":
            try:
                services.disable_totp(current_user, request.form.get("code"))
                flash("Two-factor authentication disabled")
            except ValueError as exc:
                db.session.rollback()
                flash(str(exc))
            return redirect(url_for("account.two_factor"))
        return render_template("account_2fa.html", enabled=True)

    # Enrolment: the candidate secret lives in the session until confirmed.
    secret = session.get("totp_candidate") or pyotp.random_base32()
    session["totp_candidate"] = secret
    if request.method == "POST":
        try:
            services.enable_totp(current_user, secret, request.form.get("code"))
        except ValueError as exc:
            flash(str(exc))
        else:
            session.pop("totp_candidate", None)
            flash("Two-factor authentication enabled")
            return redirect(url_for("account.overview"))
    uri = pyotp.TOTP(secret).provisioning_uri(name=current_user.username, issuer_name="Chain of Custody")
    qr_svg = segno.make(uri, error="m").svg_inline(scale=4)
    return render_template("account_2fa.html", enabled=False, secret=secret, qr_svg=qr_svg)


@bp.route("/tokens", methods=["POST"])
@require("account.self")
def token_create():
    try:
        token = services.create_api_token(current_user, request.form.get("name"))
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for("account.overview"))
    # Rendered once in this response; never stored anywhere in plain text.
    return _render_overview(new_token=token)


@bp.route("/tokens/<int:token_id>/revoke", methods=["POST"])
@require("account.self")
def token_revoke(token_id):
    try:
        services.revoke_api_token(current_user, token_id)
    except services.NotFound:
        abort(404)
    flash("Token revoked")
    return redirect(url_for("account.overview"))

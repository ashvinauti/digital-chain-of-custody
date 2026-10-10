import hashlib
import io

from flask import Blueprint, abort, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required
from sqlalchemy import select

from . import audit, db, services
from .auth import can, require
from .certificate import render_certificate
from .models import ROLES, AuditEntry, Evidence, User, utcnow_iso

bp = Blueprint("main", __name__)


def _get_evidence(evidence_id):
    ev = db.session.get(Evidence, evidence_id)
    if ev is None:
        abort(404)
    return ev


@bp.app_context_processor
def inject_can():
    return {"can": lambda perm: can(current_user, perm)}


@bp.route("/")
@login_required
def index():
    if can(current_user, "evidence.view"):
        return redirect(url_for("main.evidence_list"))
    if can(current_user, "users.manage"):
        return redirect(url_for("main.users"))
    abort(403)


@bp.route("/evidence")
@require("evidence.view")
def evidence_list():
    items = db.session.execute(select(Evidence).order_by(Evidence.id.desc())).scalars().all()
    return render_template("evidence_list.html", items=items)


@bp.route("/evidence/new", methods=["GET", "POST"])
@require("evidence.create")
def evidence_new():
    if request.method == "POST":
        f = request.files.get("file")
        case_number = request.form.get("case_number", "").strip()
        description = request.form.get("description", "").strip()
        if not f or not f.filename or not case_number or not description:
            flash("File, case number and description are all required")
            return render_template("evidence_new.html"), 400
        ev = services.ingest_evidence(f, case_number, description, current_user)
        flash(f"Evidence #{ev.id} stored. SHA-256 {ev.sha256}")
        return redirect(url_for("main.evidence_detail", evidence_id=ev.id))
    return render_template("evidence_new.html")


@bp.route("/evidence/<int:evidence_id>")
@require("evidence.view")
def evidence_detail(evidence_id):
    ev = _get_evidence(evidence_id)
    investigators = db.session.execute(
        select(User).where(User.role == "investigator", User.active.is_(True), User.id != current_user.id)
    ).scalars().all()
    return render_template(
        "evidence_detail.html", ev=ev, events=audit.entries_for_evidence(ev.id), investigators=investigators
    )


@bp.route("/evidence/<int:evidence_id>/transfer", methods=["POST"])
@require("evidence.transfer")
def evidence_transfer(evidence_id):
    ev = _get_evidence(evidence_id)
    to_user = db.session.get(User, request.form.get("to_user_id", type=int) or 0)
    try:
        services.transfer_custody(ev, to_user, request.form.get("reason", "").strip(), current_user)
    except services.CustodyError as exc:
        db.session.rollback()
        flash(f"Transfer refused: {exc}")
        return redirect(url_for("main.evidence_detail", evidence_id=ev.id))
    flash(f"Custody transferred to {to_user.username}")
    return redirect(url_for("main.evidence_detail", evidence_id=ev.id))


@bp.route("/evidence/<int:evidence_id>/verify", methods=["POST"])
@require("evidence.verify")
def evidence_verify(evidence_id):
    ev = _get_evidence(evidence_id)
    match, actual = services.verify_evidence(ev, current_user)
    flash("Hash verified: MATCH" if match else f"HASH MISMATCH: stored file hashes to {actual or 'nothing (missing)'}")
    return redirect(url_for("main.evidence_detail", evidence_id=ev.id))


@bp.route("/evidence/<int:evidence_id>/certificate", methods=["POST"])
@require("certificate.issue")
def evidence_certificate(evidence_id):
    ev = _get_evidence(evidence_id)
    file_ok, actual = services.check_evidence_integrity(ev)
    chain = audit.verify_chain()
    pdf = render_certificate(
        ev,
        audit.entries_for_evidence(ev.id),
        file_ok=file_ok,
        actual_hash=actual,
        chain=chain,
        issued_by=current_user.username,
        issued_at=utcnow_iso(),
    )
    audit.append(
        "certificate.issue",
        current_user.username,
        evidence_id=ev.id,
        details={
            "pdf_sha256": hashlib.sha256(pdf).hexdigest(),
            "file_ok": file_ok,
            "chain_ok": chain.ok,
            "chain_head": chain.head_hash,
        },
    )
    db.session.commit()
    return send_file(
        io.BytesIO(pdf),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"custody-certificate-{ev.id}.pdf",
    )


@bp.route("/audit")
@require("audit.view")
def audit_log():
    entries = db.session.execute(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(500)).scalars().all()
    return render_template("audit.html", entries=entries, chain=audit.verify_chain())


@bp.route("/admin/users", methods=["GET", "POST"])
@require("users.manage")
def users():
    status = 200
    if request.method == "POST":
        try:
            services.create_user(
                request.form.get("username", "").strip(),
                request.form.get("password", ""),
                request.form.get("role", ""),
                current_user,
            )
            flash("User created")
            return redirect(url_for("main.users"))
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc))
            status = 400
    all_users = db.session.execute(select(User).order_by(User.username)).scalars().all()
    return render_template("users.html", users=all_users, roles=ROLES), status


@bp.route("/admin/users/<int:user_id>/active", methods=["POST"])
@require("users.manage")
def user_set_active(user_id):
    user = db.session.get(User, user_id) or abort(404)
    try:
        services.set_user_active(user, request.form.get("active") == "1", current_user)
    except ValueError as exc:
        flash(str(exc))
    return redirect(url_for("main.users"))

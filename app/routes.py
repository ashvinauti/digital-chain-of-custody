import os

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required
from sqlalchemy import select

from . import audit, db, services
from .auth import can, require
from .models import CASE_ROLES, ROLES, AuditEntry, User

bp = Blueprint("main", __name__)


def _evidence(evidence_id):
    try:
        return services.get_evidence_for(current_user, evidence_id)
    except services.NotFound:
        abort(404)


def _case(case_id):
    try:
        return services.get_case_for(current_user, case_id)
    except services.NotFound:
        abort(404)


def _back(ev):
    return redirect(url_for("main.evidence_detail", evidence_id=ev.id))


@bp.app_context_processor
def inject_can():
    return {"can": lambda perm: can(current_user, perm)}


@bp.route("/")
@login_required
def index():
    if can(current_user, "cases.view"):
        return redirect(url_for("main.cases"))
    if can(current_user, "users.manage"):
        return redirect(url_for("main.users"))
    abort(403)


@bp.route("/public-key.pem")
def public_key():
    """The audit-log signing key, so anyone can check signatures offline."""
    return Response(current_app.extensions["signer"].public_pem(), mimetype="application/x-pem-file")


# --- cases ---------------------------------------------------------------------


@bp.route("/cases")
@require("cases.view")
def cases():
    return render_template("cases.html", cases=services.cases_for(current_user))


@bp.route("/cases/<int:case_id>")
@require("cases.view")
def case_detail(case_id):
    case = _case(case_id)
    return render_template("case_detail.html", case=case, items=services.visible_evidence(current_user, case.id))


@bp.route("/admin/cases", methods=["GET", "POST"])
@require("cases.manage")
def admin_cases():
    status = 200
    if request.method == "POST":
        try:
            case = services.create_case(request.form.get("number"), request.form.get("title"), current_user)
            flash(f"Case {case.number} created")
            return redirect(url_for("main.admin_case", case_id=case.id))
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc))
            status = 400
    return render_template("admin_cases.html", cases=services.cases_for(current_user)), status


@bp.route("/admin/cases/<int:case_id>", methods=["GET", "POST"])
@require("cases.manage")
def admin_case(case_id):
    case = _case(case_id)
    if request.method == "POST":
        user = db.session.get(User, request.form.get("user_id", type=int) or 0)
        try:
            if request.form.get("op") == "remove":
                services.remove_case_member(case, user, current_user)
            else:
                services.add_case_member(case, user, current_user)
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc))
        return redirect(url_for("main.admin_case", case_id=case.id))
    candidates = db.session.execute(
        select(User).where(User.role.in_(CASE_ROLES), User.active.is_(True)).order_by(User.username)
    ).scalars().all()
    candidates = [u for u in candidates if not case.has_member(u)]
    return render_template("admin_case.html", case=case, candidates=candidates)


# --- evidence ------------------------------------------------------------------


@bp.route("/evidence")
@require("evidence.view")
def evidence_list():
    return render_template("evidence_list.html", items=services.visible_evidence(current_user))


@bp.route("/evidence/new", methods=["GET", "POST"])
@require("evidence.create")
def evidence_new():
    my_cases = services.cases_for(current_user)
    if request.method == "POST":
        f = request.files.get("file")
        try:
            case = services.get_case_for(current_user, request.form.get("case_id", type=int) or 0)
            if not f or not f.filename:
                raise ValueError("choose a file")
            ev = services.ingest_evidence(
                f.stream, f.filename, case, request.form.get("description"), current_user,
                expected_sha256=request.form.get("expected_sha256"),
            )
        except services.NotFound:
            flash("Choose one of your cases")
        except (ValueError, services.CustodyError) as exc:
            flash(str(exc))
        else:
            flash(f"Evidence #{ev.id} stored. SHA-256 {ev.sha256}")
            return _back(ev)
        return render_template("evidence_new.html", cases=my_cases), 400
    return render_template("evidence_new.html", cases=my_cases, selected=request.args.get("case_id", type=int))


@bp.route("/evidence/<int:evidence_id>")
@require("evidence.view")
def evidence_detail(evidence_id):
    ev = _evidence(evidence_id)
    investigators = [m for m in ev.case.members if m.role == "investigator" and m.active and m.id != current_user.id]
    return render_template(
        "evidence_detail.html", ev=ev, events=audit.entries_for_evidence(ev.id), investigators=investigators
    )


@bp.route("/evidence/<int:evidence_id>/transfer", methods=["POST"])
@require("evidence.transfer")
def evidence_transfer(evidence_id):
    ev = _evidence(evidence_id)
    to_user = db.session.get(User, request.form.get("to_user_id", type=int) or 0)
    try:
        services.transfer_custody(ev, to_user, request.form.get("reason", "").strip(), current_user)
    except services.CustodyError as exc:
        db.session.rollback()
        flash(f"Transfer refused: {exc}")
        return _back(ev)
    flash(f"Custody transferred to {to_user.username}")
    return _back(ev)


@bp.route("/evidence/<int:evidence_id>/verify", methods=["POST"])
@require("evidence.verify")
def evidence_verify(evidence_id):
    ev = _evidence(evidence_id)
    match, actual = services.verify_evidence(ev, current_user)
    flash("Hash verified: MATCH" if match else f"HASH MISMATCH: stored file hashes to {actual or 'nothing (missing)'}")
    return _back(ev)


@bp.route("/evidence/<int:evidence_id>/certificate", methods=["POST"])
@require("certificate.issue")
def evidence_certificate(evidence_id):
    ev = _evidence(evidence_id)
    pdf = services.issue_certificate(ev, current_user)
    return send_file(pdf, mimetype="application/pdf", as_attachment=True,
                     download_name=f"custody-certificate-{ev.id}.pdf")


# --- analysis ------------------------------------------------------------------

TOOLS = ("identify", "profile", "hex", "strings", "search")


@bp.route("/evidence/<int:evidence_id>/analysis", methods=["GET", "POST"])
@require("evidence.analyze")
def evidence_analysis(evidence_id):
    ev = _evidence(evidence_id)
    tool, result, status = None, None, 200
    if request.method == "POST":
        tool = request.form.get("tool")
        if tool not in TOOLS:
            abort(400)
        params = {k: v for k, v in request.form.items() if k not in ("tool", "csrf_token") and v != ""}
        try:
            result = services.run_analysis(ev, tool, params, current_user)
        except (ValueError, services.CustodyError) as exc:
            db.session.rollback()
            flash(str(exc))
            status = 400
    notes = [e for e in audit.entries_for_evidence(ev.id) if e.action == "analysis.note"]
    return render_template("analysis.html", ev=ev, tool=tool, result=result, form=request.form, notes=notes), status


@bp.route("/evidence/<int:evidence_id>/notes", methods=["POST"])
@require("evidence.analyze")
def evidence_note(evidence_id):
    ev = _evidence(evidence_id)
    try:
        services.add_note(ev, request.form.get("text"), current_user)
        flash("Note added to the audit chain")
    except ValueError as exc:
        flash(str(exc))
    return redirect(url_for("main.evidence_analysis", evidence_id=ev.id))


@bp.route("/evidence/<int:evidence_id>/export", methods=["POST"])
@require("evidence.export")
def evidence_export(evidence_id):
    ev = _evidence(evidence_id)
    try:
        path = services.export_working_copy(ev, current_user)
    except services.CustodyError as exc:
        flash(f"Export refused: {exc}")
        return _back(ev)
    return send_file(os.path.abspath(path), as_attachment=True, download_name=ev.original_filename,
                     mimetype="application/octet-stream")


# --- certificate verification and audit ----------------------------------------


@bp.route("/certificates/verify", methods=["GET", "POST"])
@require("certificate.verify")
def certificate_verify():
    outcome = None
    if request.method == "POST":
        f = request.files.get("file")
        if not f:
            flash("Choose a PDF")
        else:
            outcome = services.check_certificate(f.read(), current_user)
    return render_template("certificate_verify.html", outcome=outcome)


@bp.route("/audit")
@require("audit.view")
def audit_log():
    entries = db.session.execute(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(500)).scalars().all()
    return render_template("audit.html", entries=entries, chain=audit.verify_chain(),
                           key_id=current_app.extensions["signer"].key_id)


# --- users -----------------------------------------------------------------------


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
                must_change_password=True,
            )
            flash("User created. They must choose a new password at first sign-in.")
            return redirect(url_for("main.users"))
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc))
            status = 400
    all_users = db.session.execute(select(User).order_by(User.username)).scalars().all()
    return render_template("users.html", users=all_users, roles=ROLES), status


@bp.route("/admin/users/<int:user_id>/<op>", methods=["POST"])
@require("users.manage")
def user_admin_action(user_id, op):
    user = db.session.get(User, user_id) or abort(404)
    try:
        if op == "active":
            services.set_user_active(user, request.form.get("active") == "1", current_user)
        elif op == "reset-password":
            services.admin_reset_password(user, request.form.get("password", ""), current_user)
            flash(f"Temporary password set for {user.username}")
        elif op == "reset-2fa":
            services.admin_reset_2fa(user, current_user)
            flash(f"Two-factor authentication reset for {user.username}")
        elif op == "unlock":
            services.admin_unlock(user, current_user)
            flash(f"{user.username} unlocked")
        else:
            abort(404)
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc))
    return redirect(url_for("main.users"))

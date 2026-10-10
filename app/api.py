"""JSON API, authenticated only by bearer token.

Tokens are created on the Account page. The API never accepts the session
cookie: a browser attaches cookies to cross-site requests automatically but
cannot be made to send an Authorization header, so ignoring cookies is what
makes it safe to exempt these routes from CSRF tokens.

Permissions and case membership are the same as in the web UI, because both
call the same @require decorator and the same services.
"""

import os

from flask import Blueprint, jsonify, request, send_file
from flask_login import current_user
from werkzeug.exceptions import HTTPException

from . import audit, csrf, db, login_manager, services
from .auth import require

bp = Blueprint("api", __name__, url_prefix="/api/v1")
csrf.exempt(bp)


@bp.before_request
def authenticate():
    header = request.headers.get("Authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else None
    user = services.user_for_token(token) if token else None
    if user is None:
        return jsonify(error="missing, invalid or revoked API token"), 401
    # Use the token's user for this request only. The session is never
    # consulted or written, so a logged-in browser cookie grants nothing here.
    login_manager._update_request_context_with_user(user)
    return None


@bp.errorhandler(HTTPException)
def json_error(exc):
    return jsonify(error=exc.description or exc.name), exc.code


def _evidence(evidence_id):
    try:
        return services.get_evidence_for(current_user, evidence_id)
    except services.NotFound:
        return None


def _not_found():
    return jsonify(error="not found"), 404


def evidence_json(ev, events=False):
    out = {
        "id": ev.id,
        "case": ev.case.number,
        "description": ev.description,
        "filename": ev.original_filename,
        "size_bytes": ev.size_bytes,
        "sha256": ev.sha256,
        "uploaded_by": ev.uploaded_by.username,
        "uploaded_at": ev.uploaded_at,
        "custodian": ev.custodian.username,
    }
    if events:
        out["events"] = [
            {"id": e.id, "timestamp": e.timestamp, "actor": e.actor, "action": e.action,
             "details": e.details, "entry_hash": e.entry_hash}
            for e in audit.entries_for_evidence(ev.id)
        ]
    return out


@bp.route("/me")
@require("account.self")
def me():
    return jsonify(username=current_user.username, role=current_user.role)


@bp.route("/cases")
@require("cases.view")
def cases():
    return jsonify([{"id": c.id, "number": c.number, "title": c.title} for c in services.cases_for(current_user)])


@bp.route("/evidence", methods=["GET"])
@require("evidence.view")
def evidence_list():
    case_id = None
    if request.args.get("case"):
        try:
            case_id = services.get_case_by_number_for(current_user, request.args["case"]).id
        except services.NotFound:
            return _not_found()
    return jsonify([evidence_json(ev) for ev in services.visible_evidence(current_user, case_id)])


@bp.route("/evidence", methods=["POST"])
@require("evidence.create")
def evidence_create():
    """multipart/form-data: file, case (number), description, expected_sha256 (optional)."""
    f = request.files.get("file")
    if not f:
        return jsonify(error="file is required"), 400
    try:
        case = services.get_case_by_number_for(current_user, request.form.get("case", ""))
        ev = services.ingest_evidence(
            f.stream, f.filename, case, request.form.get("description"), current_user,
            expected_sha256=request.form.get("expected_sha256"), via="api",
        )
    except services.NotFound:
        return jsonify(error="unknown case, or you are not assigned to it"), 404
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    except services.CustodyError as exc:
        return jsonify(error=str(exc)), 409
    return jsonify(evidence_json(ev)), 201


@bp.route("/evidence/<int:evidence_id>")
@require("evidence.view")
def evidence_get(evidence_id):
    ev = _evidence(evidence_id)
    return jsonify(evidence_json(ev, events=True)) if ev else _not_found()


@bp.route("/evidence/<int:evidence_id>/verify", methods=["POST"])
@require("evidence.verify")
def evidence_verify(evidence_id):
    ev = _evidence(evidence_id)
    if not ev:
        return _not_found()
    match, actual = services.verify_evidence(ev, current_user)
    return jsonify(match=match, expected=ev.sha256, actual=actual)


@bp.route("/evidence/<int:evidence_id>/transfer", methods=["POST"])
@require("evidence.transfer")
def evidence_transfer(evidence_id):
    """JSON: {"to": "<username>", "reason": "..."}"""
    ev = _evidence(evidence_id)
    if not ev:
        return _not_found()
    body = request.get_json(silent=True) or {}
    try:
        services.transfer_custody(ev, services.get_user(body.get("to", "")), (body.get("reason") or "").strip(), current_user)
    except services.CustodyError as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), 409
    return jsonify(evidence_json(ev))


@bp.route("/evidence/<int:evidence_id>/analysis/<tool>", methods=["POST"])
@require("evidence.analyze")
def evidence_analysis(evidence_id, tool):
    """Tools: identify, profile, hex, strings, search. Parameters as a JSON body."""
    ev = _evidence(evidence_id)
    if not ev:
        return _not_found()
    try:
        return jsonify(services.run_analysis(ev, tool, request.get_json(silent=True) or {}, current_user))
    except (ValueError, TypeError) as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), 400
    except services.CustodyError as exc:
        return jsonify(error=str(exc)), 409


@bp.route("/evidence/<int:evidence_id>/notes", methods=["POST"])
@require("evidence.analyze")
def evidence_note(evidence_id):
    """JSON: {"text": "..."}"""
    ev = _evidence(evidence_id)
    if not ev:
        return _not_found()
    try:
        entry = services.add_note(ev, (request.get_json(silent=True) or {}).get("text"), current_user)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(entry_id=entry.id, entry_hash=entry.entry_hash), 201


@bp.route("/evidence/<int:evidence_id>/export", methods=["POST"])
@require("evidence.export")
def evidence_export(evidence_id):
    ev = _evidence(evidence_id)
    if not ev:
        return _not_found()
    try:
        path = services.export_working_copy(ev, current_user)
    except services.CustodyError as exc:
        return jsonify(error=str(exc)), 409
    resp = send_file(os.path.abspath(path), as_attachment=True, download_name=ev.original_filename,
                     mimetype="application/octet-stream")
    resp.headers["X-Evidence-SHA256"] = ev.sha256
    return resp


@bp.route("/evidence/<int:evidence_id>/certificate", methods=["POST"])
@require("certificate.issue")
def evidence_certificate(evidence_id):
    ev = _evidence(evidence_id)
    if not ev:
        return _not_found()
    return send_file(services.issue_certificate(ev, current_user), mimetype="application/pdf",
                     as_attachment=True, download_name=f"custody-certificate-{ev.id}.pdf")


@bp.route("/certificates/verify", methods=["POST"])
@require("certificate.verify")
def certificate_verify():
    """Raw PDF bytes as the request body, or multipart with a `file` field."""
    data = request.files["file"].read() if "file" in request.files else request.get_data()
    return jsonify(services.check_certificate(data, current_user))


@bp.route("/audit/verify")
@require("audit.view")
def audit_verify():
    r = audit.verify_chain()
    return jsonify(ok=r.ok, entries=r.entries_checked, anchors=r.anchors_checked, head_id=r.head_id,
                   head_hash=r.head_hash, errors=[{"entry_id": e, "message": m} for e, m in r.errors])

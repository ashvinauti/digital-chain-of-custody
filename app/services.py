"""Business operations, shared by the web UI, the JSON API and the CLI.

Each one writes its audit entry in the same transaction as the change it
records, so a change never happens without its log entry or vice versa.
"""

import hashlib
import json
import os
import re
import secrets
import uuid
from datetime import timedelta

import pyotp
from flask import current_app
from sqlalchemy import select

from . import analysis, audit, db
from .hashing import sha256_file, store_and_hash
from .models import CASE_ROLES, ROLES, ApiToken, Case, Evidence, User, utcnow, utcnow_iso


class CustodyError(Exception):
    """A request that is well-formed but not allowed in the current state."""


class NotFound(Exception):
    """The object does not exist, or the user is not allowed to know it does."""


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


# --- users and accounts --------------------------------------------------------


def validate_password(password):
    if len(password or "") < 12:
        raise ValueError("password must be at least 12 characters")


def get_user(username):
    return db.session.execute(select(User).where(User.username == username)).scalar_one_or_none()


def create_user(username, password, role, actor, must_change_password=False):
    if role not in ROLES:
        raise ValueError(f"unknown role {role}")
    if not username or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username):
        raise ValueError("username must be 1-64 letters, digits, '.', '_' or '-'")
    validate_password(password)
    if get_user(username):
        raise ValueError("username already exists")
    user = User(username=username, role=role, must_change_password=must_change_password)
    user.set_password(password)
    db.session.add(user)
    audit.append("user.create", actor.username if actor else "system", details={"username": username, "role": role})
    db.session.commit()
    return user


def set_user_active(user, active, actor):
    if user.id == actor.id:
        raise ValueError("you cannot deactivate yourself")
    user.active = active
    if not active:
        _revoke_all_tokens(user)
    audit.append("user.activate" if active else "user.deactivate", actor.username, details={"username": user.username})
    db.session.commit()


def admin_reset_password(user, temp_password, actor):
    """Set a temporary password the user must change at next sign-in.
    Also unlocks the account and revokes its API tokens."""
    validate_password(temp_password)
    user.set_password(temp_password)
    user.must_change_password = True
    user.failed_logins = 0
    user.locked_until = None
    _revoke_all_tokens(user)
    audit.append("user.password_reset", actor.username, details={"username": user.username})
    db.session.commit()


def admin_reset_2fa(user, actor):
    user.totp_secret = None
    user.totp_last_step = None
    audit.append("user.2fa_reset", actor.username, details={"username": user.username})
    db.session.commit()


def admin_unlock(user, actor):
    user.failed_logins = 0
    user.locked_until = None
    audit.append("user.unlock", actor.username, details={"username": user.username})
    db.session.commit()


def change_own_password(user, current_password, new_password):
    if not user.check_password(current_password):
        raise ValueError("current password is incorrect")
    validate_password(new_password)
    if current_password == new_password:
        raise ValueError("new password must differ from the current one")
    user.set_password(new_password)
    user.must_change_password = False
    audit.append("auth.password_change", user.username)
    db.session.commit()


def record_failed_login(user, username, ip, reason):
    """Count a failure; lock the account after MAX_FAILED_LOGINS."""
    details = {"ip": ip, "reason": reason}
    if user is not None:
        user.failed_logins += 1
        if user.failed_logins >= current_app.config["MAX_FAILED_LOGINS"]:
            minutes = current_app.config["LOCKOUT_MINUTES"]
            user.locked_until = (utcnow() + timedelta(minutes=minutes)).isoformat()
            user.failed_logins = 0
            audit.append("auth.lockout", user.username, details={"ip": ip, "minutes": minutes})
    audit.append("auth.login_failed", (username or "-")[:64], details=details)
    db.session.commit()


def record_login(user, ip, method):
    user.failed_logins = 0
    user.locked_until = None
    audit.append("auth.login", user.username, details={"ip": ip, "method": method})
    db.session.commit()


def verify_totp(user, code):
    """Check a 6-digit code, allowing one 30 s step of clock drift, and
    refuse a code (time step) that was already used."""
    code = (code or "").strip().replace(" ", "")
    if not user.totp_secret or not re.fullmatch(r"\d{6}", code):
        return False
    totp = pyotp.TOTP(user.totp_secret)
    now_step = totp.timecode(utcnow())
    for step in (now_step - 1, now_step, now_step + 1):
        if secrets.compare_digest(totp.generate_otp(step), code):
            if user.totp_last_step is not None and step <= user.totp_last_step:
                return False  # replay
            user.totp_last_step = step
            return True
    return False


def enable_totp(user, secret, code):
    candidate = pyotp.TOTP(secret)
    step = candidate.timecode(utcnow())
    if not any(secrets.compare_digest(candidate.generate_otp(s), (code or "").strip()) for s in (step - 1, step, step + 1)):
        raise ValueError("code did not match; check your authenticator app's clock")
    user.totp_secret = secret
    user.totp_last_step = step
    audit.append("auth.2fa_enabled", user.username)
    db.session.commit()


def disable_totp(user, code):
    if not verify_totp(user, code):
        raise ValueError("invalid code")
    user.totp_secret = None
    user.totp_last_step = None
    audit.append("auth.2fa_disabled", user.username)
    db.session.commit()


# --- API tokens ----------------------------------------------------------------


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_api_token(user, name):
    name = (name or "").strip()[:64]
    if not name:
        raise ValueError("token name required")
    token = "coc_" + secrets.token_urlsafe(32)
    db.session.add(ApiToken(user_id=user.id, name=name, token_hash=hash_token(token)))
    audit.append("api.token_create", user.username, details={"name": name})
    db.session.commit()
    return token  # shown once; only the hash is stored


def revoke_api_token(user, token_id):
    tok = db.session.get(ApiToken, token_id)
    if tok is None or tok.user_id != user.id:
        raise NotFound()
    tok.revoked = True
    audit.append("api.token_revoke", user.username, details={"name": tok.name})
    db.session.commit()


def user_for_token(token):
    tok = db.session.execute(
        select(ApiToken).where(ApiToken.token_hash == hash_token(token or ""))
    ).scalar_one_or_none()
    if tok is None or tok.revoked or not tok.user.active or tok.user.must_change_password:
        return None
    tok.last_used_at = utcnow_iso()
    db.session.commit()
    return tok.user


def _revoke_all_tokens(user):
    for tok in db.session.execute(select(ApiToken).where(ApiToken.user_id == user.id)).scalars():
        tok.revoked = True


# --- cases ---------------------------------------------------------------------


def create_case(number, title, actor):
    number, title = (number or "").strip(), (title or "").strip()
    if not number or not title:
        raise ValueError("case number and title are required")
    if db.session.execute(select(Case).where(Case.number == number)).scalar_one_or_none():
        raise ValueError("case number already exists")
    case = Case(number=number, title=title)
    db.session.add(case)
    audit.append("case.create", actor.username if actor else "system", details={"number": number, "title": title})
    db.session.commit()
    return case


def add_case_member(case, user, actor):
    if user is None or user.role not in CASE_ROLES:
        raise ValueError("only investigators and reviewers can be case members")
    if case.has_member(user):
        raise ValueError(f"{user.username} is already a member")
    case.members.append(user)
    audit.append("case.member_add", actor.username if actor else "system",
                 details={"case": case.number, "username": user.username})
    db.session.commit()


def remove_case_member(case, user, actor):
    if not case.has_member(user):
        raise ValueError(f"{user.username} is not a member")
    held = [ev.id for ev in case.evidence if ev.custodian_id == user.id]
    if held:
        raise ValueError(f"{user.username} is custodian of evidence {held}; transfer custody first")
    case.members.remove(user)
    audit.append("case.member_remove", actor.username, details={"case": case.number, "username": user.username})
    db.session.commit()


def cases_for(user):
    if user.role == "admin":
        return db.session.execute(select(Case).order_by(Case.number)).scalars().all()
    return sorted(user.cases, key=lambda c: c.number)


def get_case_for(user, case_id):
    case = db.session.get(Case, case_id)
    if case is None or (user.role != "admin" and not case.has_member(user)):
        raise NotFound()
    return case


def get_case_by_number_for(user, number):
    case = db.session.execute(select(Case).where(Case.number == number)).scalar_one_or_none()
    if case is None or not case.has_member(user):
        raise NotFound()
    return case


# --- evidence ------------------------------------------------------------------


def visible_evidence(user, case_id=None):
    q = select(Evidence).join(Evidence.case).where(Case.members.any(User.id == user.id))
    if case_id is not None:
        q = q.where(Evidence.case_id == case_id)
    return db.session.execute(q.order_by(Evidence.id.desc())).scalars().all()


def get_evidence_for(user, evidence_id):
    """Evidence in a case the user belongs to. Anything else is NotFound, so
    non-members cannot even learn that an id exists."""
    ev = db.session.get(Evidence, evidence_id)
    if ev is None or not ev.case.has_member(user):
        raise NotFound()
    return ev


def evidence_path(evidence):
    return os.path.join(current_app.config["EVIDENCE_DIR"], evidence.storage_name)


def ingest_evidence(stream, filename, case, description, actor, expected_sha256=None, via="web"):
    """Store and hash an evidence file.

    `expected_sha256` is the hash from the acquisition tool (e.g. FTK Imager
    or dc3dd). If given and different, the file is rejected: it changed
    between acquisition and ingest.
    """
    if actor.role != "investigator" or not case.has_member(actor):
        raise CustodyError("only investigators assigned to the case can add evidence")
    description = (description or "").strip()
    if not description:
        raise ValueError("description is required")
    expected = (expected_sha256 or "").strip().lower() or None
    if expected and not SHA256_RE.match(expected):
        raise ValueError("expected SHA-256 must be 64 hex characters")

    storage_name = uuid.uuid4().hex
    dest = os.path.join(current_app.config["EVIDENCE_DIR"], storage_name)
    sha256, size = store_and_hash(stream, dest)
    filename = os.path.basename(filename or "") or "unnamed"

    def discard():
        os.chmod(dest, 0o600)
        os.remove(dest)

    if expected and expected != sha256:
        discard()
        audit.append(
            "evidence.ingest_rejected",
            actor.username,
            details={"case": case.number, "filename": filename, "expected": expected, "actual": sha256, "via": via},
        )
        db.session.commit()
        raise CustodyError(f"hash mismatch: acquisition hash {expected}, received file hashes to {sha256}")

    try:
        ev = Evidence(
            case_id=case.id,
            description=description,
            original_filename=filename,
            storage_name=storage_name,
            size_bytes=size,
            sha256=sha256,
            uploaded_by_id=actor.id,
            custodian_id=actor.id,
        )
        db.session.add(ev)
        db.session.flush()
        audit.append(
            "evidence.upload",
            actor.username,
            evidence_id=ev.id,
            details={
                "case": case.number,
                "filename": filename,
                "sha256": sha256,
                "size_bytes": size,
                "custodian": actor.username,
                "acquisition_hash_matched": bool(expected),
                "via": via,
            },
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        discard()
        raise
    return ev


def transfer_custody(evidence, to_user, reason, actor):
    if evidence.custodian_id != actor.id:
        raise CustodyError("only the current custodian can transfer this item")
    if to_user is None or not to_user.active or to_user.role != "investigator":
        raise CustodyError("custody can only be transferred to an active investigator")
    if not evidence.case.has_member(to_user):
        raise CustodyError(f"{to_user.username} is not assigned to case {evidence.case.number}")
    if to_user.id == actor.id:
        raise CustodyError("item is already in your custody")
    if not reason:
        raise CustodyError("a reason is required")
    evidence.custodian_id = to_user.id
    audit.append(
        "custody.transfer",
        actor.username,
        evidence_id=evidence.id,
        details={"from": actor.username, "to": to_user.username, "reason": reason},
    )
    db.session.commit()


def chained_upload_hash(evidence):
    """The SHA-256 recorded in the hash-chained upload entry. Unlike the
    `evidence.sha256` column, changing it would break the audit chain."""
    for entry in audit.entries_for_evidence(evidence.id):
        if entry.action == "evidence.upload":
            return json.loads(entry.details).get("sha256")
    return None


def check_evidence_integrity(evidence):
    """Re-hash the stored file. Returns (match, actual_hash_or_None)."""
    try:
        actual = sha256_file(evidence_path(evidence))
    except FileNotFoundError:
        actual = None
    match = actual is not None and actual == evidence.sha256 == chained_upload_hash(evidence)
    return match, actual


def verify_evidence(evidence, actor):
    """Re-hash the stored file and record the outcome."""
    match, actual = check_evidence_integrity(evidence)
    audit.append(
        "evidence.verify",
        actor.username,
        evidence_id=evidence.id,
        details={"expected": evidence.sha256, "actual": actual or "FILE MISSING", "match": match},
    )
    db.session.commit()
    return match, actual


# --- analysis ------------------------------------------------------------------


def run_analysis(evidence, tool, params, actor):
    """Run a read-only tool and log who looked at what."""
    path = evidence_path(evidence)
    if not os.path.exists(path):
        raise CustodyError("evidence file is missing from storage")
    if tool == "identify":
        result = analysis.identify(path)
        summary = {"type": result["type"]}
    elif tool == "profile":
        result = analysis.profile(path)
        summary = {k: result[k] for k in ("md5", "sha1", "sha256", "entropy_bits_per_byte")}
        if result["sha256"] != evidence.sha256:
            summary["warning"] = "SHA-256 differs from acquisition hash"
    elif tool == "hex":
        result = analysis.hexdump(path, params.get("offset", 0), params.get("length", 512))
        params = {"offset": result["offset"], "length": result["length"]}
        summary = {}
    elif tool == "strings":
        result = analysis.extract_strings(
            path, params.get("encoding", "ascii"), params.get("min_len", 6), params.get("limit", 500), params.get("start", 0)
        )
        summary = {"count": len(result["strings"])}
    elif tool == "search":
        result = analysis.search(path, params.get("keyword", ""), params.get("max_hits", 200))
        summary = {"hits": len(result["hits"])}
    else:
        raise ValueError(f"unknown tool {tool}")
    audit.append(
        "analysis.run", actor.username, evidence_id=evidence.id,
        details={"tool": tool, "params": params, "result": summary},
    )
    db.session.commit()
    return result


def add_note(evidence, text, actor):
    text = (text or "").strip()
    if not text:
        raise ValueError("note text is required")
    if len(text) > 5000:
        raise ValueError("notes are limited to 5000 characters")
    entry = audit.append("analysis.note", actor.username, evidence_id=evidence.id, details={"text": text})
    db.session.commit()
    return entry


def export_working_copy(evidence, actor):
    """Path of a verified file for the current custodian to analyse with
    external tools. Refused (and logged) if the stored file fails its hash."""
    if evidence.custodian_id != actor.id:
        raise CustodyError("only the current custodian can export a working copy")
    match, actual = check_evidence_integrity(evidence)
    if not match:
        audit.append("evidence.export_refused", actor.username, evidence_id=evidence.id,
                     details={"expected": evidence.sha256, "actual": actual or "FILE MISSING"})
        db.session.commit()
        raise CustodyError("stored file failed hash verification; export refused")
    audit.append("evidence.export", actor.username, evidence_id=evidence.id, details={"sha256": actual})
    db.session.commit()
    return evidence_path(evidence)


# --- certificates ----------------------------------------------------------------


def find_certificate_entry(pdf_bytes):
    """The certificate.issue entry that recorded this exact PDF, if any."""
    from .models import AuditEntry

    digest = hashlib.sha256(pdf_bytes).hexdigest()
    entry = db.session.execute(
        select(AuditEntry).where(
            AuditEntry.action == "certificate.issue",
            AuditEntry.details.contains(f'"pdf_sha256":"{digest}"'),
        )
    ).scalars().first()
    return digest, entry


def issue_certificate(evidence, actor):
    """Render the PDF, record its SHA-256 in a signed log entry, then anchor
    the new head so the certificate's entry can't be silently truncated away."""
    import io

    from .certificate import render_certificate

    file_ok, actual = check_evidence_integrity(evidence)
    chain = audit.verify_chain()
    pdf = render_certificate(
        evidence,
        audit.entries_for_evidence(evidence.id),
        file_ok=file_ok,
        actual_hash=actual,
        chain=chain,
        key_id=audit.signer().key_id,
        issued_by=actor.username,
        issued_at=utcnow_iso(),
    )
    audit.append(
        "certificate.issue",
        actor.username,
        evidence_id=evidence.id,
        details={
            "pdf_sha256": hashlib.sha256(pdf).hexdigest(),
            "file_ok": file_ok,
            "chain_ok": chain.ok,
            "chain_head": chain.head_hash,
        },
    )
    db.session.commit()
    audit.anchor()
    return io.BytesIO(pdf)


def check_certificate(pdf_bytes, actor):
    """Was this exact PDF issued by this system, and is its record intact?"""
    digest, entry = find_certificate_entry(pdf_bytes)
    outcome = {"pdf_sha256": digest, "valid": False}
    if entry is None:
        outcome["reason"] = "No certificate with this SHA-256 was issued here. The file was modified or is not genuine."
    else:
        recomputed = audit.compute_entry_hash(
            id=entry.id, timestamp=entry.timestamp, actor=entry.actor, action=entry.action,
            evidence_id=entry.evidence_id, details=entry.details, prev_hash=entry.prev_hash,
        )
        signed = recomputed == entry.entry_hash and audit.signer().verify(entry.signature, entry.entry_hash.encode())
        ev = db.session.get(Evidence, entry.evidence_id)
        member = ev is not None and ev.case.has_member(actor)
        outcome.update(
            valid=signed,
            reason=None if signed else "The log entry recording this certificate fails its hash or signature check.",
            entry_id=entry.id,
            issued_at=entry.timestamp,
            issued_by=entry.actor,
            # Only case members learn which evidence it covers.
            evidence_id=entry.evidence_id if member else None,
            certified_ok=json.loads(entry.details).get("file_ok") and json.loads(entry.details).get("chain_ok"),
        )
    audit.append("certificate.check", actor.username, details={"pdf_sha256": digest, "valid": outcome["valid"]})
    db.session.commit()
    return outcome

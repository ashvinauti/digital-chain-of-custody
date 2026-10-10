"""Business operations. Each one writes its audit entry in the same
transaction as the change it records."""

import json
import os
import uuid

from flask import current_app
from sqlalchemy import select

from . import audit, db
from .hashing import sha256_file, store_and_hash
from .models import ROLES, Evidence, User


class CustodyError(Exception):
    pass


def create_user(username, password, role, actor):
    if role not in ROLES:
        raise ValueError(f"unknown role {role}")
    if not username or len(password) < 12:
        raise ValueError("username required and password must be at least 12 characters")
    if db.session.execute(select(User).where(User.username == username)).scalar_one_or_none():
        raise ValueError("username already exists")
    user = User(username=username, role=role)
    user.set_password(password)
    db.session.add(user)
    audit.append("user.create", actor.username if actor else "system", details={"username": username, "role": role})
    db.session.commit()
    return user


def set_user_active(user, active, actor):
    if user.id == actor.id:
        raise ValueError("you cannot deactivate yourself")
    user.active = active
    audit.append("user.activate" if active else "user.deactivate", actor.username, details={"username": user.username})
    db.session.commit()


def evidence_path(evidence):
    return os.path.join(current_app.config["EVIDENCE_DIR"], evidence.storage_name)


def ingest_evidence(file_storage, case_number, description, actor):
    storage_name = uuid.uuid4().hex
    dest = os.path.join(current_app.config["EVIDENCE_DIR"], storage_name)
    sha256, size = store_and_hash(file_storage.stream, dest)
    try:
        ev = Evidence(
            case_number=case_number,
            description=description,
            original_filename=file_storage.filename or "unnamed",
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
                "case_number": case_number,
                "filename": ev.original_filename,
                "sha256": sha256,
                "size_bytes": size,
                "custodian": actor.username,
            },
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        os.chmod(dest, 0o600)
        os.remove(dest)
        raise
    return ev


def transfer_custody(evidence, to_user, reason, actor):
    if evidence.custodian_id != actor.id:
        raise CustodyError("only the current custodian can transfer this item")
    if to_user is None or not to_user.active or to_user.role != "investigator":
        raise CustodyError("custody can only be transferred to an active investigator")
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

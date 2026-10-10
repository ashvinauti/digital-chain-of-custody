from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from . import db, login_manager

ROLES = ("investigator", "reviewer", "admin")
# Roles that can be members of a case (admins manage cases but never see evidence).
CASE_ROLES = ("investigator", "reviewer")


def utcnow():
    return datetime.now(timezone.utc)


def utcnow_iso():
    return utcnow().isoformat(timespec="microseconds")


case_members = db.Table(
    "case_members",
    db.Column("case_id", db.Integer, db.ForeignKey("cases.id"), primary_key=True),
    db.Column("user_id", db.Integer, db.ForeignKey("users.id"), primary_key=True),
)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(16), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.String(40), nullable=False, default=utcnow_iso)
    must_change_password = db.Column(db.Boolean, nullable=False, default=False)
    failed_logins = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.String(40), nullable=True)  # ISO-8601 UTC
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_last_step = db.Column(db.Integer, nullable=True)  # replay protection

    cases = db.relationship("Case", secondary=case_members, back_populates="members")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        return self.active

    @property
    def is_locked(self):
        return bool(self.locked_until) and datetime.fromisoformat(self.locked_until) > utcnow()

    @property
    def totp_enabled(self):
        return self.totp_secret is not None


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class Case(db.Model):
    __tablename__ = "cases"

    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(64), unique=True, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.String(40), nullable=False, default=utcnow_iso)

    members = db.relationship("User", secondary=case_members, back_populates="cases", order_by="User.username")
    evidence = db.relationship("Evidence", back_populates="case", order_by="Evidence.id")

    def has_member(self, user):
        return any(m.id == user.id for m in self.members)


class Evidence(db.Model):
    __tablename__ = "evidence"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    storage_name = db.Column(db.String(64), unique=True, nullable=False)
    size_bytes = db.Column(db.BigInteger, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    uploaded_at = db.Column(db.String(40), nullable=False, default=utcnow_iso)
    # Convenience pointer; the audit log is the authoritative custody history.
    custodian_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    case = db.relationship("Case", back_populates="evidence")
    uploaded_by = db.relationship("User", foreign_keys=[uploaded_by_id])
    custodian = db.relationship("User", foreign_keys=[custodian_id])


class ApiToken(db.Model):
    """A bearer token for the JSON API. Only its SHA-256 is stored."""

    __tablename__ = "api_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    name = db.Column(db.String(64), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.String(40), nullable=False, default=utcnow_iso)
    last_used_at = db.Column(db.String(40), nullable=True)
    revoked = db.Column(db.Boolean, nullable=False, default=False)

    user = db.relationship("User")


class AuditEntry(db.Model):
    """One link in the append-only, hash-chained audit log.

    entry_hash = SHA-256(canonical JSON of every other content field, including prev_hash).
    signature  = Ed25519 signature of entry_hash by the server's signing key.
    prev_hash is unique, so two entries can never claim the same predecessor
    (prevents a fork if two writers race).
    """

    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(40), nullable=False)
    actor = db.Column(db.String(64), nullable=False)
    action = db.Column(db.String(64), nullable=False)
    evidence_id = db.Column(db.Integer, nullable=True, index=True)
    details = db.Column(db.Text, nullable=False)  # canonical JSON
    prev_hash = db.Column(db.String(64), nullable=False, unique=True)
    entry_hash = db.Column(db.String(64), nullable=False, unique=True)
    key_id = db.Column(db.String(16), nullable=False)
    signature = db.Column(db.String(128), nullable=False)

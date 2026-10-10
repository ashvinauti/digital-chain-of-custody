"""Digital chain-of-custody platform: application factory."""

import json
import os

import click
from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import inspect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()


def _env_flag(name, default="0"):
    return os.environ.get(name, default) == "1"


def create_app(config_overrides=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///custody.db"),
        EVIDENCE_DIR=os.environ.get("EVIDENCE_DIR", os.path.join(app.instance_path, "evidence")),
        SIGNING_KEY_PATH=os.environ.get("SIGNING_KEY_PATH", os.path.join(app.instance_path, "signing_key.pem")),
        # Should be on different storage from the database: ideally write-once or off-host.
        ANCHOR_FILE=os.environ.get("ANCHOR_FILE", os.path.join(app.instance_path, "anchors.jsonl")),
        MAX_CONTENT_LENGTH=int(os.environ.get("MAX_UPLOAD_MB", "512")) * 1024 * 1024,
        MAX_FAILED_LOGINS=int(os.environ.get("MAX_FAILED_LOGINS", "5")),
        LOCKOUT_MINUTES=int(os.environ.get("LOCKOUT_MINUTES", "15")),
        REQUIRE_2FA=_env_flag("REQUIRE_2FA"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=_env_flag("SESSION_COOKIE_SECURE"),
    )
    if config_overrides:
        app.config.update(config_overrides)
    if not app.config["SECRET_KEY"]:
        raise RuntimeError("SECRET_KEY must be set")

    os.makedirs(app.config["EVIDENCE_DIR"], exist_ok=True)

    from .signing import Signer

    app.extensions["signer"] = Signer.load_or_create(app.config["SIGNING_KEY_PATH"])

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    csrf.init_app(app)

    from . import models
    from .account import bp as account_bp
    from .api import bp as api_bp
    from .audit import install_append_only_triggers
    from .auth import bp as auth_bp
    from .routes import bp as main_bp

    for bp in (auth_bp, account_bp, main_bp, api_bp):
        app.register_blueprint(bp)
    app.jinja_env.filters["fromjson"] = json.loads

    with app.app_context():
        _refuse_v1_database()
        db.create_all()
        install_append_only_triggers()
        # Don't let pooled connections opened here leak into forked
        # gunicorn workers (--preload); each worker must open its own.
        db.engine.dispose()

    _register_cli(app, models)
    return app


def _refuse_v1_database():
    insp = inspect(db.engine)
    old = (insp.has_table("evidence") and "case_id" not in {c["name"] for c in insp.get_columns("evidence")}) or (
        insp.has_table("audit_log") and "signature" not in {c["name"] for c in insp.get_columns("audit_log")}
    )
    if old:
        raise RuntimeError(
            "This database was created by v1, and v2 needs a fresh one (cases and signed audit entries). "
            "Delete the instance/ folder (local) or run `docker compose down -v` (Docker), then start again."
        )


def _register_cli(app, models):
    from . import audit, services

    @app.cli.command("create-user")
    @click.argument("username")
    @click.argument("role", type=click.Choice(models.ROLES))
    @click.password_option()
    def create_user_cmd(username, role, password):
        """Create a user (use this to bootstrap the first admin)."""
        services.create_user(username, password, role, actor=None)
        click.echo(f"created {role} {username}")

    @app.cli.command("bootstrap-admin")
    def bootstrap_admin_cmd():
        """Create an admin from ADMIN_USERNAME/ADMIN_PASSWORD if no users exist."""
        if db.session.query(models.User).count():
            click.echo("users already exist; skipping")
            return
        username, password = os.environ.get("ADMIN_USERNAME"), os.environ.get("ADMIN_PASSWORD")
        if not username or not password:
            raise click.ClickException("set ADMIN_USERNAME and ADMIN_PASSWORD")
        services.create_user(username, password, "admin", actor=None)
        click.echo(f"created admin {username}")

    @app.cli.command("verify-log")
    @click.option("--expect-head", default=None, help="A head hash recorded earlier (e.g. on a certificate).")
    def verify_log_cmd(expect_head):
        """Verify hashes, links, signatures and anchors; exits non-zero on failure."""
        result = audit.verify_chain(expected_head=expect_head)
        click.echo(result.summary())
        if not result.ok:
            raise SystemExit(1)

    @app.cli.command("anchor")
    def anchor_cmd():
        """Append a signed record of the current log head to ANCHOR_FILE (run from cron)."""
        a = audit.anchor()
        click.echo(f"anchored entry {a['entry_id']} {a['head_hash']}" if a else "nothing new to anchor")

    @app.cli.command("ingest")
    @click.argument("path", type=click.Path(exists=True, dir_okay=False))
    @click.option("--case", "case_number", required=True, help="Case number the evidence belongs to.")
    @click.option("--description", required=True)
    @click.option("--as", "username", required=True, help="Investigator recorded as acquirer and first custodian.")
    @click.option("--expected-sha256", default=None, help="Hash from the acquisition tool; mismatch rejects the file.")
    def ingest_cmd(path, case_number, description, username, expected_sha256):
        """Ingest a large file from disk (no upload size limit)."""
        user = services.get_user(username)
        if user is None or not user.active:
            raise click.ClickException(f"no active user {username}")
        try:
            case = services.get_case_by_number_for(user, case_number)
        except services.NotFound:
            raise click.ClickException(f"case {case_number} not found or {username} is not assigned to it")
        try:
            with open(path, "rb") as fh:
                ev = services.ingest_evidence(fh, os.path.basename(path), case, description, user,
                                              expected_sha256=expected_sha256, via="cli")
        except (ValueError, services.CustodyError) as exc:
            raise click.ClickException(str(exc))
        click.echo(f"evidence {ev.id} stored: sha256 {ev.sha256}, {ev.size_bytes} bytes")

    @app.cli.command("verify-certificate")
    @click.argument("path", type=click.Path(exists=True, dir_okay=False))
    def verify_certificate_cmd(path):
        """Check that a certificate PDF was issued here and its record is intact."""
        with open(path, "rb") as fh:
            digest, entry = services.find_certificate_entry(fh.read())
        if entry is None:
            click.echo(f"NOT FOUND: no certificate with sha256 {digest} was issued here")
            raise SystemExit(1)
        ok = audit.signer().verify(entry.signature, entry.entry_hash.encode())
        chain = audit.verify_chain()
        click.echo(f"{'VALID' if ok and chain.ok else 'INVALID'}: issued {entry.timestamp} by {entry.actor} "
                   f"for evidence {entry.evidence_id} (entry {entry.id}); chain {'OK' if chain.ok else 'FAILED'}")
        if not (ok and chain.ok):
            raise SystemExit(1)

"""Digital chain-of-custody platform: application factory."""

import os

import click
from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()


def create_app(config_overrides=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///custody.db"),
        EVIDENCE_DIR=os.environ.get("EVIDENCE_DIR", os.path.join(app.instance_path, "evidence")),
        MAX_CONTENT_LENGTH=int(os.environ.get("MAX_UPLOAD_MB", "512")) * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    )
    if config_overrides:
        app.config.update(config_overrides)
    if not app.config["SECRET_KEY"]:
        raise RuntimeError("SECRET_KEY must be set")

    os.makedirs(app.config["EVIDENCE_DIR"], exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    csrf.init_app(app)

    from . import models  # noqa: F401  (register models)
    from .audit import install_append_only_triggers
    from .auth import bp as auth_bp
    from .routes import bp as main_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    with app.app_context():
        db.create_all()
        install_append_only_triggers()
        # Don't let pooled connections opened here leak into forked
        # gunicorn workers (--preload); each worker must open its own.
        db.engine.dispose()

    @app.cli.command("create-user")
    @click.argument("username")
    @click.argument("role", type=click.Choice(models.ROLES))
    @click.password_option()
    def create_user_cmd(username, role, password):
        """Create a user (use this to bootstrap the first admin)."""
        from .services import create_user

        create_user(username, password, role, actor=None)
        click.echo(f"created {role} {username}")

    @app.cli.command("bootstrap-admin")
    def bootstrap_admin_cmd():
        """Create an admin from ADMIN_USERNAME/ADMIN_PASSWORD if no users exist."""
        from .services import create_user

        if db.session.query(models.User).count():
            click.echo("users already exist; skipping")
            return
        username, password = os.environ.get("ADMIN_USERNAME"), os.environ.get("ADMIN_PASSWORD")
        if not username or not password:
            raise click.ClickException("set ADMIN_USERNAME and ADMIN_PASSWORD")
        create_user(username, password, "admin", actor=None)
        click.echo(f"created admin {username}")

    @app.cli.command("verify-log")
    @click.option("--expect-head", default=None, help="A head hash recorded earlier (e.g. on a certificate).")
    def verify_log_cmd(expect_head):
        """Verify the audit log hash chain; exits non-zero on failure."""
        from .audit import verify_chain

        result = verify_chain(expected_head=expect_head)
        click.echo(result.summary())
        if not result.ok:
            raise SystemExit(1)

    return app

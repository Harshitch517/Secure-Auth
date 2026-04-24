"""
app/__init__.py — Application factory.

create_app() wires together:
  - Configuration (from config.py)
  - Extensions (db, login_manager, bcrypt, csrf, limiter, mail)
  - Blueprints (auth, dashboard)
  - Error handlers (403, 404, 429)
  - Database table creation + admin seed on first run
  - Top-level routes (index /)
"""

from flask import Flask, render_template, redirect, url_for
from flask_login import current_user

from app.config import Config
from app.extensions import db, login_manager, bcrypt, csrf, limiter, mail


def create_app(config_class=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)

    # ── Initialise extensions ─────────────────────────────────────────────────
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    mail.init_app(app)

    # ── Register blueprints ───────────────────────────────────────────────────
    from app.auth import auth_bp
    from app.dashboard import dashboard_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    # ── Top-level routes ──────────────────────────────────────────────────────

    @app.route("/")
    def index():
        """Landing page — redirect to dashboard if already logged in."""
        if current_user.is_authenticated:
            return redirect(url_for("dashboard.dashboard_redirect"))
        return render_template("index.html")

    # ── Error handlers ────────────────────────────────────────────────────────

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(429)
    def too_many_requests(e):
        from flask import flash
        flash("Too many requests. Please slow down and try again later.", "warning")
        return redirect(url_for("auth.login"))

    # ── Database + seed ───────────────────────────────────────────────────────
    with app.app_context():
        from app.models.user import User       # noqa: F401
        from app.models.otp import OTPToken    # noqa: F401
        from app.models.audit_log import AuditLog  # noqa: F401

        db.create_all()
        _seed_admin(app)

    return app


def _seed_admin(app: Flask) -> None:
    """
    Creates a default admin account if no admin user exists yet.
    Credentials come from config (which reads from .env).
    This function is idempotent — safe to call on every startup.
    """
    from app.models.user import User

    if User.query.filter_by(email=app.config["ADMIN_EMAIL"]).first():
        return  # Seed user already exists

    pw_hash = bcrypt.generate_password_hash(
        app.config["ADMIN_PASSWORD"]
    ).decode("utf-8")

    admin = User(
        username="admin",
        email=app.config["ADMIN_EMAIL"],
        password_hash=pw_hash,
        role="admin",
        email_verified=True,
    )
    db.session.add(admin)
    db.session.commit()

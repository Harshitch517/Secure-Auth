"""
app/config.py — Application configuration.

All sensitive values are read from environment variables (populated from .env).
Never hardcode secrets here.
"""

import os
from datetime import timedelta


class Config:
    # ── Flask core ────────────────────────────────────────────────────────────
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "change-me-in-production")

    # ── Database (SQLite, single file, zero config) ───────────────────────────
    # SQLAlchemy prepends 'sqlite:///' so the path becomes relative to where
    # Flask's 'instance' folder lives, but we override with an absolute path
    # to keep the db file next to the project root.
    _db_url = os.environ.get("DATABASE_URL", "sqlite:///auth.db")
    SQLALCHEMY_DATABASE_URI: str = _db_url
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    # ── Session cookies ───────────────────────────────────────────────────────
    PERMANENT_SESSION_LIFETIME: timedelta = timedelta(hours=2)
    SESSION_COOKIE_HTTPONLY: bool = True   # JS cannot read the cookie → XSS protection
    SESSION_COOKIE_SAMESITE: str = "Lax"  # CSRF mitigation
    # SESSION_COOKIE_SECURE = True         # Uncomment when serving over HTTPS

    # ── CSRF ──────────────────────────────────────────────────────────────────
    WTF_CSRF_ENABLED: bool = True
    WTF_CSRF_TIME_LIMIT: int = 3600  # 1 hour token validity

    # ── Rate limiting (in-memory, no Redis needed) ────────────────────────────
    RATELIMIT_STORAGE_URI: str = "memory://"
    RATELIMIT_DEFAULT: str = "500 per day;100 per hour"

    # ── Brute-force lockout policy ────────────────────────────────────────────
    MAX_LOGIN_ATTEMPTS: int = 5       # consecutive failures before lockout
    LOCKOUT_DURATION_MINUTES: int = 15

    # ── OTP settings ──────────────────────────────────────────────────────────
    OTP_EXPIRY_MINUTES: int = 10      # email OTP valid window

    # ── Admin seed account (created on first run if no admin exists) ──────────
    ADMIN_EMAIL: str = os.environ.get("ADMIN_EMAIL", "admin@secureauth.local")
    ADMIN_PASSWORD: str = os.environ.get("ADMIN_PASSWORD", "Admin@SecureAuth123!")

    # ── Email Configuration ───────────────────────────────────────────────────
    MAIL_SERVER: str = os.environ.get("MAIL_SERVER", "")
    MAIL_PORT: int = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS: bool = os.environ.get("MAIL_USE_TLS", "True").lower() in ["true", "1", "yes"]
    MAIL_USERNAME: str = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD: str = os.environ.get("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER: str = os.environ.get("MAIL_DEFAULT_SENDER", "noreply@secureauth.local")

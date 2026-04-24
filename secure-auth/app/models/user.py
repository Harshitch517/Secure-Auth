"""
app/models/user.py — User database model.

Security-relevant columns:
  password_hash       — bcrypt hash, never plain text
  role                — 'user' | 'admin'
  email_verified      — must be True before a session is granted
  failed_login_attempts / locked_until — brute-force protection
"""

from datetime import datetime
from app.extensions import db, login_manager
from flask_login import UserMixin


class User(UserMixin, db.Model):
    __tablename__ = "users"

    # ── Primary key ───────────────────────────────────────────────────────────
    id = db.Column(db.Integer, primary_key=True)

    # ── Identity ──────────────────────────────────────────────────────────────
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)

    # ── Authorization ─────────────────────────────────────────────────────────
    role = db.Column(db.String(20), nullable=False, default="user")

    # ── Email verification ────────────────────────────────────────────────────
    email_verified = db.Column(db.Boolean, default=False, nullable=False)

    # ── Brute-force protection ────────────────────────────────────────────────
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

    # ── Audit timestamps ──────────────────────────────────────────────────────
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    # ── Relationships ─────────────────────────────────────────────────────────
    otp_tokens = db.relationship(
        "OTPToken", back_populates="user", cascade="all, delete-orphan"
    )
    audit_logs = db.relationship(
        "AuditLog", back_populates="user", cascade="all, delete-orphan"
    )

    # ── Helper methods ────────────────────────────────────────────────────────
    def is_locked(self) -> bool:
        """Returns True if the account is currently locked out."""
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False

    def __repr__(self) -> str:
        return f"<User {self.username!r} role={self.role!r}>"


# ── Flask-Login user loader ───────────────────────────────────────────────────
@login_manager.user_loader
def load_user(user_id: str):
    """Called by Flask-Login to reload the user from the session cookie."""
    return User.query.get(int(user_id))

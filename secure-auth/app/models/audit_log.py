"""
app/models/audit_log.py — Immutable security audit trail.

Every sensitive action (login, logout, MFA setup, role change, lockout, etc.)
is written here.  Rows are append-only; no update or delete paths exist.

The admin dashboard reads these records to provide visibility into system
activity — a key defence against privilege misuse.
"""

from datetime import datetime
from app.extensions import db


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)

    # Nullable because we log some events (e.g. unknown-user login attempts)
    # even before a user is identified
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # Short, machine-readable action code (e.g. 'LOGIN_SUCCESS', 'ROLE_CHANGE')
    action = db.Column(db.String(64), nullable=False)

    # IPv4 or IPv6 address (max 45 chars for IPv6 with zone ID)
    ip_address = db.Column(db.String(45), nullable=True)

    # Human-readable extra context; never contains passwords or secrets
    details = db.Column(db.Text, nullable=True)

    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationship — may be None if user_id is None
    user = db.relationship("User", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog {self.action!r} user_id={self.user_id}>"

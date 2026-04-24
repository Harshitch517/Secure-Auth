"""
app/models/otp.py — Short-lived email OTP tokens.

Each row stores a single 6-digit code for one user.  The code expires after
OTP_EXPIRY_MINUTES (config) and can only be used once (used=True on success).
Expiry is enforced at the application layer by comparing datetime values.
"""

from datetime import datetime
from app.extensions import db


class OTPToken(db.Model):
    __tablename__ = "otp_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # The 6-digit numeric code (stored as a zero-padded string e.g. "007142")
    code = db.Column(db.String(6), nullable=False)

    # Naive UTC datetime — compared with datetime.utcnow()
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Back-reference to the owner
    user = db.relationship("User", back_populates="otp_tokens")

    # ── Validity helpers ──────────────────────────────────────────────────────
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        """A token is valid only if it has not been used and has not expired."""
        return not self.used and not self.is_expired()

    def __repr__(self) -> str:
        return f"<OTPToken user_id={self.user_id} used={self.used}>"

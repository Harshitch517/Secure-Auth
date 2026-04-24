"""
app/auth/helpers.py — Reusable auth utility functions.

These are pure helper functions, not route handlers.  They are called from
routes.py and from security/decorators.py.

Key functions:
  generate_otp(user)           → creates & stores a 6-digit OTP, returns code
  verify_otp(user, code)       → constant-time check; marks token used on success
  check_lockout(user)          → True if account is currently locked
  record_failed_attempt(user)  → increments counter; locks if threshold reached
  reset_failed_attempts(user)  → clears counter on successful login
  log_audit(user, action, …)   → writes an AuditLog row
"""

import hmac
import secrets
from datetime import datetime, timedelta

from flask import current_app, request, session
from flask_mail import Message

from app.extensions import db, mail
from app.models.otp import OTPToken
from app.models.audit_log import AuditLog


# ── OTP helpers ───────────────────────────────────────────────────────────────

def generate_otp(user) -> str:
    """
    Generate a cryptographically secure 6-digit OTP.

    Steps:
      1. Invalidate any existing unused OTP tokens for this user
         (prevents reuse of old codes after a new one is requested).
      2. Create a new OTPToken row with a future expiry timestamp.
      3. Return the plaintext code for display (simulating email delivery).
    """
    # Invalidate stale tokens first
    OTPToken.query.filter_by(user_id=user.id, used=False).delete()

    code = f"{secrets.randbelow(1_000_000):06d}"  # cryptographically random
    expiry = datetime.utcnow() + timedelta(
        minutes=current_app.config["OTP_EXPIRY_MINUTES"]
    )

    token = OTPToken(
        user_id=user.id,
        code=code,
        expires_at=expiry,
    )
    db.session.add(token)
    db.session.commit()
    return code


def check_otp_rate_limit() -> tuple[bool, str]:
    """
    Enforces OTP generation limits:
      - Max 3 requests per hour
      - 30 second cooldown between requests
    Returns (True, "") if allowed.
    Returns (False, "error message") if rate limited.
    """
    now = datetime.utcnow().timestamp()
    
    # Get OTP history from session
    history = session.get("otp_history", [])
    
    # Filter out requests older than 1 hour (3600 seconds)
    history = [t for t in history if now - t < 3600]
    
    # Check 1 hour limit
    if len(history) >= 3:
        session["otp_history"] = history # save filtered history
        return False, "You can only request 3 OTPs per hour. Please try again later."
        
    # Check 30 seconds cooldown
    if history and (now - history[-1] < 30):
        wait_time = int(30 - (now - history[-1]))
        return False, f"Please wait {wait_time} seconds before requesting another code."
        
    # Valid request, update history
    history.append(now)
    session["otp_history"] = history
    return True, ""


def send_otp_email(user, code: str, reason: str = "verification") -> bool:
    """
    Sends the generated OTP code to the user's email address.

    Returns True if the email was dispatched successfully, False otherwise.
    Always prints the code to the server console as a fallback so the
    developer can retrieve it during local testing.
    """
    # Always log to console so it's retrievable during development
    print(f"[OTP] {reason.upper()} code for {user.email}: {code}", flush=True)

    if not current_app.config.get("MAIL_SERVER"):
        print("[OTP] MAIL_SERVER not configured — email not sent.", flush=True)
        return False

    subject = "SecureAuth - Your Verification Code"
    if reason == "password_reset":
        subject = "SecureAuth - Password Reset Code"

    msg = Message(
        subject=subject,
        recipients=[user.email],
        body=(
            f"Hello {user.username},\n\n"
            f"Your 6-digit verification code is: {code}\n\n"
            f"This code will expire in {current_app.config['OTP_EXPIRY_MINUTES']} minutes.\n\n"
            f"If you did not request this, please ignore this email."
        )
    )

    try:
        mail.send(msg)
        print(f"[OTP] Email sent successfully to {user.email}.", flush=True)
        return True
    except Exception as e:
        print(f"[OTP] Failed to send email to {user.email}: {e}", flush=True)
        return False


def verify_otp(user, submitted_code: str) -> bool:
    """
    Check the submitted OTP code against the most recent valid token.

    Security properties:
    - Uses hmac.compare_digest() for constant-time comparison → no timing leak.
    - Marks the token as used on success → one-time use enforced.
    - Expired or already-used tokens are rejected.
    """
    token = (
        OTPToken.query
        .filter_by(user_id=user.id, used=False)
        .order_by(OTPToken.created_at.desc())
        .first()
    )

    if not token or not token.is_valid():
        return False

    # Constant-time comparison prevents timing-based code enumeration
    if hmac.compare_digest(token.code, submitted_code.strip()):
        token.used = True
        db.session.commit()
        return True

    return False


# ── Brute-force / lockout helpers ─────────────────────────────────────────────

def check_lockout(user) -> bool:
    """Returns True if the user's account is currently locked."""
    return user.is_locked()


def record_failed_attempt(user) -> None:
    """
    Increment the failed-login counter.
    If the counter reaches MAX_LOGIN_ATTEMPTS, the account is locked for
    LOCKOUT_DURATION_MINUTES minutes.
    """
    user.failed_login_attempts += 1
    max_attempts = current_app.config["MAX_LOGIN_ATTEMPTS"]
    lockout_minutes = current_app.config["LOCKOUT_DURATION_MINUTES"]

    if user.failed_login_attempts >= max_attempts:
        user.locked_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)
        log_audit(
            user=user,
            action="ACCOUNT_LOCKED",
            details=(
                f"Locked for {lockout_minutes} min after "
                f"{user.failed_login_attempts} consecutive failures"
            ),
        )

    db.session.commit()


def reset_failed_attempts(user) -> None:
    """
    Clear the failure counter and lockout timestamp after a successful
    password check.  Also records the last-login timestamp.
    """
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.utcnow()
    db.session.commit()


# ── Audit logging ─────────────────────────────────────────────────────────────

def log_audit(user, action: str, details: str = None) -> None:
    """
    Append a security-relevant event to the audit log.

    Parameters:
        user    — the User object (or None for anonymous events)
        action  — short uppercase action code (e.g. 'LOGIN_SUCCESS')
        details — optional human-readable context; MUST NOT contain secrets
    """
    entry = AuditLog(
        user_id=user.id if user and hasattr(user, "id") else None,
        action=action,
        ip_address=request.remote_addr,
        details=details,
    )
    db.session.add(entry)
    db.session.commit()

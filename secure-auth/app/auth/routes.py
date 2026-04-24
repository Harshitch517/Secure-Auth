"""
app/auth/routes.py — All authentication route handlers.

2-Factor Authentication Flow:

REGISTRATION:
  POST /auth/register     → validate form + password policy
                            → store pending data in SESSION (no DB write yet)
                            → generate OTP → send via email → /otp-verify
  POST /auth/otp-verify   → verify OTP → create User in DB → login → dashboard

LOGIN:
  POST /auth/login        → check password → check lockout
                            → generate OTP → send via email → /login-otp
  POST /auth/login-otp    → verify OTP → full login

FORGOT PASSWORD:
  POST /auth/forgot-password → send OTP to email → /reset-password
  POST /auth/reset-password  → verify OTP + new password

GET /auth/logout          → clear session → redirect to login
"""

import hmac as _hmac
import secrets as _secrets

from flask import (
    render_template, redirect, url_for, flash, session, current_app,
)
from flask_login import login_user, logout_user, login_required, current_user

from app.auth import auth_bp
from app.extensions import db, bcrypt, limiter
from app.models.user import User
from app.auth.forms import (
    RegistrationForm, LoginForm, OTPForm,
    ForgotPasswordForm, ResetPasswordForm,
)
from app.auth.helpers import (
    generate_otp, verify_otp, check_lockout,
    record_failed_attempt, reset_failed_attempts, log_audit, send_otp_email,
    check_otp_rate_limit,
)
from app.security.validators import validate_password_strength, sanitize_username


# ─────────────────────────────────────────────────────────────────────────────
# REGISTRATION — Step 1: collect credentials, send OTP
# ─────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """
    Step 1 of registration: validate credentials and send OTP email.

    The user record is NOT written to the database here.
    All registration data is stored in the server-side Flask session.
    The DB row is only created in otp_verify() after the OTP is confirmed.
    This prevents ghost/orphaned accounts in the users table.
    """
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard_redirect"))

    form = RegistrationForm()

    if form.validate_on_submit():
        # ── Password policy check ──────────────────────────────────────────
        pw_errors = validate_password_strength(form.password.data)
        if pw_errors:
            for err in pw_errors:
                flash(err, "danger")
            return render_template("auth/register.html", form=form)

        email_clean = form.email.data.lower().strip()

        # ── Reject if email already exists ────────────────────────────────
        if User.query.filter_by(email=email_clean).first():
            flash("An account with that email already exists.", "danger")
            return render_template("auth/register.html", form=form)

        clean_username = sanitize_username(form.username.data)

        # ── Reject if username already taken ──────────────────────────────
        if User.query.filter_by(username=clean_username).first():
            flash("That username is already taken.", "danger")
            return render_template("auth/register.html", form=form)

        # ── Hash password ─────────────────────────────────────────────────
        pw_hash = bcrypt.generate_password_hash(form.password.data).decode("utf-8")

        # ── Check OTP rate limit ──────────────────────────────────────────
        allowed, msg = check_otp_rate_limit()
        if not allowed:
            flash(msg, "warning")
            return render_template("auth/register.html", form=form)

        # ── Generate cryptographically secure OTP ─────────────────────────
        otp_code = f"{_secrets.randbelow(1_000_000):06d}"

        # ── Store everything in session (no DB row created yet) ────────────
        session["s_pending_reg"] = {
            "username": clean_username,
            "email": email_clean,
            "pw_hash": pw_hash,
            "role": "user",
        }
        session["s_pending_otp"] = otp_code

        # ── Send OTP via email ─────────────────────────────────────────────
        class _PendingUser:
            username = clean_username
            email = email_clean

        sent = send_otp_email(_PendingUser(), otp_code, "verification")
        if sent:
            flash(
                f"A 6-digit verification code has been sent to {email_clean}. "
                "Enter it below to complete registration.",
                "otp",
            )
        else:
            flash(
                f"Email delivery failed. Your code is: {otp_code}",
                "otp",
            )

        return redirect(url_for("auth.otp_verify"))

    return render_template("auth/register.html", form=form)


# ─────────────────────────────────────────────────────────────────────────────
# REGISTRATION — Step 2: verify OTP, create user, log in
# ─────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/otp-verify", methods=["GET", "POST"])
def otp_verify():
    """
    Registration OTP verification.
    Only after OTP is confirmed do we write the User row to the database.
    """
    pending = session.get("s_pending_reg")
    pending_otp = session.get("s_pending_otp")

    if not pending or not pending_otp:
        flash("Session expired. Please register again.", "warning")
        return redirect(url_for("auth.register"))

    form = OTPForm()
    if form.validate_on_submit():
        submitted = form.code.data.strip()

        # Constant-time comparison prevents timing attacks
        if _hmac.compare_digest(pending_otp, submitted):
            # ── OTP correct → NOW create the user in the DB ──────────────
            user = User(
                username=pending["username"],
                email=pending["email"],
                password_hash=pending["pw_hash"],
                role=pending["role"],
                email_verified=True,
            )
            db.session.add(user)
            db.session.commit()

            session.pop("s_pending_reg", None)
            session.pop("s_pending_otp", None)

            log_audit(user=user, action="REGISTER", details="Account created and email verified")
            login_user(user, remember=False)
            flash(f"Welcome, {user.username}! Your account is ready.", "success")
            return redirect(url_for("dashboard.dashboard_redirect"))
        else:
            flash("Invalid code. Please try again.", "danger")

    return render_template("auth/otp_verify.html", form=form, purpose="register")


# ─────────────────────────────────────────────────────────────────────────────
# LOGIN — Step 1: verify password, send OTP
# ─────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute;30 per hour")
def login():
    """
    Factor 1: Password verification.

    Security measures:
    - Generic error prevents email enumeration
    - Dummy bcrypt check on unknown email prevents timing attacks
    - Account lockout after MAX_LOGIN_ATTEMPTS consecutive failures
    - All failures are logged to the audit trail
    """
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard_redirect"))

    form = LoginForm()

    if form.validate_on_submit():
        email    = form.email.data.lower().strip()
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        _generic_error = "Invalid email or password."

        if not user:
            # Dummy bcrypt hash — prevents timing-based user enumeration
            bcrypt.check_password_hash(
                "$2b$12$KIXhn3b3HHTfQBm7DnHHZuHZR8GVmKt6kaTmXqYlxiXvFW.2nj/De",
                password,
            )
            flash(_generic_error, "danger")
            return render_template("auth/login.html", form=form)

        # ── Account lockout check ──────────────────────────────────────────
        if check_lockout(user):
            flash(
                "Your account is temporarily locked due to too many failed attempts. "
                "Please try again in 15 minutes.",
                "warning",
            )
            return render_template("auth/login.html", form=form)

        # ── Password verification ──────────────────────────────────────────
        if not bcrypt.check_password_hash(user.password_hash, password):
            record_failed_attempt(user)
            remaining = max(
                0,
                current_app.config["MAX_LOGIN_ATTEMPTS"] - user.failed_login_attempts,
            )
            log_audit(user=user, action="LOGIN_FAILED", details="Wrong password")

            if user.is_locked():
                flash("Too many failed attempts. Account locked for 15 minutes.", "warning")
            else:
                flash(f"{_generic_error} {remaining} attempt(s) remaining.", "danger")
            return render_template("auth/login.html", form=form)

        # ── Password correct — reset counter, send OTP ─────────────────────
        reset_failed_attempts(user)
        log_audit(user=user, action="LOGIN_PASSWORD_OK")

        # ── Check OTP rate limit ──────────────────────────────────────────
        allowed, msg = check_otp_rate_limit()
        if not allowed:
            flash(msg, "warning")
            return render_template("auth/login.html", form=form)

        otp = generate_otp(user)
        session["s_login_uid"] = user.id

        sent = send_otp_email(user, otp, "login")
        if sent:
            flash(
                f"A verification code has been sent to {user.email}. "
                "Enter it below to complete sign-in.",
                "otp",
            )
        else:
            flash(f"Email delivery failed. Your code is: {otp}", "otp")

        return redirect(url_for("auth.login_otp"))

    return render_template("auth/login.html", form=form)


# ─────────────────────────────────────────────────────────────────────────────
# LOGIN — Step 2: verify OTP, complete login
# ─────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/login-otp", methods=["GET", "POST"])
def login_otp():
    """
    Factor 2: Email OTP verification.
    Completes the login after password was accepted.
    """
    user_id = session.get("s_login_uid")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = User.query.get(user_id)
    if not user:
        session.pop("s_login_uid", None)
        return redirect(url_for("auth.login"))

    form = OTPForm()

    if form.validate_on_submit():
        if verify_otp(user, form.code.data):
            session.pop("s_login_uid", None)
            login_user(user, remember=False)
            log_audit(user=user, action="LOGIN_SUCCESS", details="2FA OTP verified")
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("dashboard.dashboard_redirect"))
        else:
            log_audit(user=user, action="OTP_FAILED", details="Login OTP mismatch")
            flash("Invalid or expired code. Please try again.", "danger")

    return render_template("auth/otp_verify.html", form=form, purpose="login")


# ─────────────────────────────────────────────────────────────────────────────
# FORGOT PASSWORD
# ─────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Request a password reset — sends OTP to the account email."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard_redirect"))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        user = User.query.filter_by(email=email).first()

        if user:
            # ── Check OTP rate limit ──────────────────────────────────────────
            allowed, msg = check_otp_rate_limit()
            if not allowed:
                flash(msg, "warning")
                return render_template("auth/forgot_password.html", form=form)

            otp = generate_otp(user)
            session["s_reset_uid"] = user.id
            log_audit(user=user, action="PASSWORD_RESET_REQUESTED")
            sent = send_otp_email(user, otp, "password_reset")
            if sent:
                flash(
                    "A reset code has been sent to your email. It expires in 10 minutes.",
                    "otp",
                )
            else:
                flash(f"Email failed. Your reset code is: {otp}", "otp")
            return redirect(url_for("auth.reset_password"))
        else:
            # Generic message — prevents account enumeration
            flash("If an account with that email exists, a code was sent.", "info")
            return redirect(url_for("auth.login"))

    return render_template("auth/forgot_password.html", form=form)


# ─────────────────────────────────────────────────────────────────────────────
# RESET PASSWORD
# ─────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    """Verify OTP and set a new password."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard_redirect"))

    user_id = session.get("s_reset_uid")
    if not user_id:
        flash("Session expired. Please request a new reset.", "warning")
        return redirect(url_for("auth.forgot_password"))

    user = User.query.get(user_id)
    if not user:
        session.pop("s_reset_uid", None)
        return redirect(url_for("auth.forgot_password"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        if verify_otp(user, form.code.data):
            pw_errors = validate_password_strength(form.password.data)
            if pw_errors:
                for err in pw_errors:
                    flash(err, "danger")
                return render_template("auth/reset_password.html", form=form)

            user.password_hash = bcrypt.generate_password_hash(
                form.password.data
            ).decode("utf-8")
            db.session.commit()

            session.pop("s_reset_uid", None)
            log_audit(user=user, action="PASSWORD_RESET_COMPLETED")
            flash("Password reset successfully. You can now sign in.", "success")
            return redirect(url_for("auth.login"))
        else:
            log_audit(user=user, action="OTP_FAILED", details="Password reset code invalid")
            flash("Invalid or expired code. Please try again.", "danger")

    return render_template("auth/reset_password.html", form=form)


# ─────────────────────────────────────────────────────────────────────────────
# LOGOUT
# ─────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout")
@login_required
def logout():
    """Terminate the session and redirect to login."""
    log_audit(user=current_user, action="LOGOUT")
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))

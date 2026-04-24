"""
app/auth/forms.py — WTForms form classes for the auth blueprint.

Flask-WTF automatically adds a hidden CSRF token to every form rendered with
{{ form.csrf_token }}. All POST requests without a valid token return 400.

Input length validators provide buffer overflow / injection protection —
inputs that fail validation never reach the database layer.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import (
    DataRequired,
    Email,
    Length,
    EqualTo,
    Regexp,
)
from app.models.user import User


class RegistrationForm(FlaskForm):
    """New-account creation form."""

    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Username is required."),
            Length(min=3, max=64, message="Username must be 3–64 characters."),
            Regexp(
                r"^[\w]+$",
                message="Only letters, numbers, and underscores are allowed.",
            ),
        ],
    )

    email = StringField(
        "Email",
        validators=[
            DataRequired(message="Email is required."),
            Email(message="Enter a valid email address."),
            Length(max=120),
        ],
    )

    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Password is required."),
            Length(
                min=12,
                max=128,
                message="Password must be 12–128 characters.",
            ),
        ],
    )

    confirm_password = PasswordField(
        "Confirm password",
        validators=[
            DataRequired(message="Please confirm your password."),
            EqualTo("password", message="Passwords do not match."),
        ],
    )

    submit = SubmitField("Send verification code")


class LoginForm(FlaskForm):
    """Credentials form for existing users."""

    email = StringField(
        "Email",
        validators=[
            DataRequired(message="Email is required."),
            Email(message="Enter a valid email address."),
        ],
    )

    password = PasswordField(
        "Password",
        validators=[DataRequired(message="Password is required.")],
    )

    submit = SubmitField("Continue")


class OTPForm(FlaskForm):
    """6-digit email OTP entry form."""

    code = StringField(
        "Verification code",
        validators=[
            DataRequired(message="Code is required."),
            Length(min=6, max=6, message="Code must be exactly 6 digits."),
            Regexp(r"^\d{6}$", message="Code must be 6 digits."),
        ],
    )

    submit = SubmitField("Verify")


class ForgotPasswordForm(FlaskForm):
    """Request a password reset email."""

    email = StringField(
        "Email",
        validators=[
            DataRequired(message="Email is required."),
            Email(message="Enter a valid email address."),
        ],
    )

    submit = SubmitField("Send reset code")


class ResetPasswordForm(FlaskForm):
    """Enter OTP and new password."""

    code = StringField(
        "Verification code",
        validators=[
            DataRequired(message="Code is required."),
            Length(min=6, max=6, message="Code must be exactly 6 digits."),
            Regexp(r"^\d{6}$", message="Code must be 6 digits."),
        ],
    )

    password = PasswordField(
        "New password",
        validators=[
            DataRequired(message="Password is required."),
            Length(min=12, max=128, message="Password must be 12–128 characters."),
        ],
    )

    confirm_password = PasswordField(
        "Confirm new password",
        validators=[
            DataRequired(message="Please confirm your password."),
            EqualTo("password", message="Passwords do not match."),
        ],
    )

    submit = SubmitField("Reset password")

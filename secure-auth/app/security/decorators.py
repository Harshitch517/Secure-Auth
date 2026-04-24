"""
app/security/decorators.py — Route-level access control decorators.

@role_required(*roles)
    Restricts a view function to users that hold one of the listed roles.
    Any access by a user without the required role is:
      1. Logged to the audit trail (PRIVILEGE_VIOLATION)
      2. Responded to with HTTP 403

Usage:
    @dashboard_bp.route('/admin')
    @login_required          # ← always check authentication first
    @role_required('admin')  # ← then check authorisation
    def admin_panel():
        ...
"""

from functools import wraps
from flask import abort
from flask_login import current_user


def role_required(*roles: str):
    """
    Decorator factory.  Call with one or more role strings.

    Examples:
        @role_required('admin')
        @role_required('admin', 'moderator')
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Authentication guard (belt-and-suspenders alongside @login_required)
            if not current_user.is_authenticated:
                from flask import redirect, url_for
                return redirect(url_for("auth.login"))

            if current_user.role != "superadmin" and current_user.role not in roles:
                # Log the privilege-misuse attempt before rejecting
                from app.auth.helpers import log_audit
                log_audit(
                    user=current_user,
                    action="PRIVILEGE_VIOLATION",
                    details=(
                        f"Attempted access to {roles!r}-only endpoint "
                        f"with role={current_user.role!r}"
                    ),
                )
                abort(403)

            return f(*args, **kwargs)

        return decorated_function

    return decorator

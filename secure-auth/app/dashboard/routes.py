"""
app/dashboard/routes.py — Role-gated dashboard pages.

Routes:
  /dashboard/       → redirect based on role
  /dashboard/user   → any authenticated user
  /dashboard/admin  → admin only (users list + audit log)
  /dashboard/admin/change-role/<uid>/<role> → admin only (POST)
"""

from flask import render_template, redirect, url_for, flash, abort, request
from flask_login import login_required, current_user

from app.dashboard import dashboard_bp
from app.extensions import db
from app.models.user import User
from app.models.audit_log import AuditLog
from app.security.decorators import role_required
from app.auth.helpers import log_audit


@dashboard_bp.route("/")
@login_required
def dashboard_redirect():
    """Redirect to the appropriate dashboard based on role."""
    if current_user.role == "admin":
        return redirect(url_for("dashboard.admin_dashboard"))
    return redirect(url_for("dashboard.user_dashboard"))


# ─────────────────────────────────────────────────────────────────────────────
# USER DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

@dashboard_bp.route("/user")
@login_required
def user_dashboard():
    """Show account info and security status."""
    return render_template("dashboard/user.html")


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

@dashboard_bp.route("/admin")
@login_required
@role_required("admin")
def admin_dashboard():
    """Users table and audit log."""
    users = User.query.order_by(User.created_at.desc()).all()
    logs  = (
        AuditLog.query
        .order_by(AuditLog.timestamp.desc())
        .limit(100)
        .all()
    )
    return render_template("dashboard/admin.html", users=users, logs=logs)


# ─────────────────────────────────────────────────────────────────────────────
# ROLE MANAGEMENT (admin only)
# ─────────────────────────────────────────────────────────────────────────────

@dashboard_bp.route("/admin/change-role/<int:user_id>/<string:new_role>", methods=["POST"])
@login_required
@role_required("admin")
def change_role(user_id: int, new_role: str):
    """
    Change a user's role.
    - Only 'admin' role can reach this endpoint (@role_required)
    - Admins cannot change their own role
    - Only predefined role strings are accepted (buffer overflow / injection guard)
    - CSRF token validated globally by Flask-WTF
    """
    # Input validation — only accept known role strings
    valid_roles = {"user", "admin"}
    if new_role not in valid_roles:
        abort(400)

    if user_id == current_user.id:
        flash("You cannot change your own role.", "warning")
        return redirect(url_for("dashboard.admin_dashboard"))

    target = User.query.get_or_404(user_id)
    old_role = target.role
    target.role = new_role
    db.session.commit()

    log_audit(
        user=current_user,
        action="ROLE_CHANGE",
        details=f"Changed {target.username!r}: {old_role} → {new_role}",
    )
    flash(f"{target.username} is now a {new_role}.", "success")
    return redirect(url_for("dashboard.admin_dashboard"))

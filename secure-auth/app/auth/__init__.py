"""
app/auth/__init__.py — Auth blueprint package.

The Blueprint is defined here and imported by the application factory
(app/__init__.py).  Routes are imported after the blueprint is created
to avoid circular imports.
"""

from flask import Blueprint

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

# Import routes after creating the blueprint so they can reference auth_bp
from app.auth import routes  # noqa: E402, F401

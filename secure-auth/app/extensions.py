"""
app/extensions.py — Flask extension instances.

All extensions are created here (without an app) and later initialised inside
create_app() via the init_app() pattern. This avoids circular imports between
the app factory and the blueprints that use these extensions.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail

# ── Database ORM ──────────────────────────────────────────────────────────────
# Uses SQLAlchemy; all queries go through the ORM → no raw string interpolation
# → SQL injection is structurally prevented.
db = SQLAlchemy()

# ── Session management ────────────────────────────────────────────────────────
login_manager = LoginManager()
login_manager.login_view = "auth.login"           # redirect unauthenticated users here
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"       # regenerate session on each request

# ── Password hashing ──────────────────────────────────────────────────────────
# bcrypt with default cost factor (12) — adaptive; slows brute-force attacks.
bcrypt = Bcrypt()

# ── CSRF protection ───────────────────────────────────────────────────────────
# Automatically protects every POST/PUT/PATCH/DELETE form with a hidden token.
csrf = CSRFProtect()

# ── Rate limiting (in-memory) ─────────────────────────────────────────────────
# Tracks request counts per IP address in RAM.  No Redis required.
# Specific limits are applied per-route with @limiter.limit().
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=["500 per day", "100 per hour"],
)

# ── Email Delivery ────────────────────────────────────────────────────────────
mail = Mail()

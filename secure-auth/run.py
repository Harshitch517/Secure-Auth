"""
run.py — Application entry point.

Usage:
    python run.py

The app starts at http://127.0.0.1:5000

Default seeded admin credentials:
    Email:    admin@secureauth.local
    Password: Admin@SecureAuth123!
    (Set up TOTP on first login)
"""

import os
from dotenv import load_dotenv

# Load .env before importing the app so config picks up all variables
load_dotenv()

from app import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print()
    print("  ====================================")
    print("     SecureAuth is running!")
    print(f"     http://127.0.0.1:{port}")
    print("  ------------------------------------")
    print("     Admin: admin@secureauth.local")
    print("     Pass:  Admin@SecureAuth123!")
    print("     Press Ctrl+C to stop")
    print("  ====================================")
    print()
    # debug=False even in dev — prevents code reload surprises
    app.run(host="127.0.0.1", port=port, debug=False)

"""
app/security/validators.py — Input validation utilities.

validate_password_strength():
    Enforces the strong password policy required by the project spec.
    Returns a list of human-readable error strings (empty = valid).

sanitize_username():
    Strips non-alphanumeric/underscore characters and truncates to safe length.
    Defence-in-depth: input sanitization before it ever touches the DB.
"""

import re

# A minimal list of the most common passwords — reject these outright
COMMON_PASSWORDS = {
    "password", "password1", "password123", "Password1!", "12345678",
    "123456789", "qwerty123", "qwertyuiop", "abc123456", "letmein123",
    "monkey123", "dragon123", "sunshine1", "princess1", "welcome123",
    "shadow123", "superman1", "michael123", "football1", "iloveyou1",
}


def validate_password_strength(password: str) -> list:
    """
    Validates a password against the project's strong password policy:
      - At least 12 characters
      - No more than 128 characters (defence against DoS via long bcrypt input)
      - At least one uppercase letter
      - At least one lowercase letter
      - At least one digit
      - At least one special character
      - Not in the common-passwords list

    Returns:
        list[str]: Error messages.  Empty list means the password is valid.
    """
    errors = []

    if len(password) < 12:
        errors.append("Password must be at least 12 characters long.")

    if len(password) > 128:
        errors.append("Password must not exceed 128 characters.")

    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")

    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")

    if not re.search(r"\d", password):
        errors.append("Password must contain at least one number.")

    if not re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:\'",.<>?/`~\\]', password):
        errors.append("Password must contain at least one special character.")

    if password.lower() in COMMON_PASSWORDS or password in COMMON_PASSWORDS:
        errors.append("Password is too common — please choose something unique.")

    return errors


def sanitize_username(username: str) -> str:
    """
    Strips all characters that are not alphanumeric or underscores,
    trims surrounding whitespace, and truncates to 64 characters.

    This is defence-in-depth; the WTForms validator on the form already
    rejects invalid usernames before we reach here.
    """
    return re.sub(r"[^\w]", "", username.strip())[:64]

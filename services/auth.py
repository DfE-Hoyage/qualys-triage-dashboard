import os
from functools import wraps
from flask import redirect, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

DEMO_USERNAME = os.environ.get("APP_DEMO_USER", "analyst@dfe.example.gov.uk")
DEMO_PASSWORD_HASH = generate_password_hash(os.environ.get("APP_DEMO_PASS", "QualysTriage2026!"))


def verify_credentials(username: str, password: str) -> bool:
    if username.strip().lower() != DEMO_USERNAME.lower():
        return False
    return check_password_hash(DEMO_PASSWORD_HASH, password)


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("frontend.login"))
        return view_func(*args, **kwargs)
    return wrapped_view

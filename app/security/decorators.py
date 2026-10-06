from functools import wraps

from flask import abort, g, redirect, session, url_for

from app.models.db import get_db
from app.security.audit import log_event
from app.security.sessions import get_valid_session


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        row = get_valid_session()
        if row is None:
            session.clear()
            return redirect(url_for("auth.login"))
        g.user = row
        return f(*args, **kwargs)
    return wrapper


def has_permission(user_id, code):
    row = get_db().execute(
        "SELECT 1 FROM users u "
        "JOIN role_permissions rp ON rp.role_id = u.role_id "
        "JOIN permissions p ON p.id = rp.permission_id "
        "WHERE u.id = ? AND p.code = ?", (user_id, code)).fetchone()
    return row is not None


def require_permission(code):
    def deco(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            if not has_permission(g.user["user_id"], code):
                log_event("ACCESS_DENIED", g.user["user_id"], details=code)
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return deco
from flask import (Blueprint, abort, flash, g, redirect, render_template,
                   request, url_for)

from app.extensions import limiter
from app.models.db import get_db
from app.security.audit import log_event, verify_chain
from app.security.decorators import require_permission

bp = Blueprint("admin", __name__, url_prefix="/admin")

VALID_ROLES = {"user": 1, "admin": 2}
ADMIN_ROLE_ID = 2


def is_last_admin(user_id):
    """True si user_id est administrateur ET le seul qui reste."""
    db = get_db()
    me = db.execute("SELECT role_id FROM users WHERE id = ?",
                    (user_id,)).fetchone()
    if me is None or me["role_id"] != ADMIN_ROLE_ID:
        return False
    count = db.execute("SELECT COUNT(*) FROM users WHERE role_id = ?",
                       (ADMIN_ROLE_ID,)).fetchone()[0]
    return count <= 1


@bp.route("/logs")
@require_permission("logs:read")
def logs():
    rows = get_db().execute(
        "SELECT id, event_type, user_id, ip, details, created_at "
        "FROM security_logs ORDER BY id DESC LIMIT 100").fetchall()
    return render_template("admin_logs.html", logs=rows)


@bp.route("/logs/integrity", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
@require_permission("logs:read")
def log_integrity():
    result = None
    if request.method == "POST":
        # 1. La vérification est en lecture seule...
        result = verify_chain()
        # 2. ...puis l'action de l'admin est journalisée (écriture distincte).
        summary = ("intégrité vérifiée" if result["ok"]
                   else f"{len(result['anomalies'])} anomalie(s)")
        log_event("LOG_INTEGRITY_CHECK", g.user["user_id"], details=summary)
    return render_template("admin_log_integrity.html", r=result)


@bp.route("/users")
@require_permission("users:manage")
def users():
    rows = get_db().execute(
        "SELECT u.id, u.email, r.name AS role, u.locked_until, "
        "(u.mfa_secret IS NOT NULL) AS mfa "
        "FROM users u JOIN roles r ON r.id = u.role_id "
        "ORDER BY u.id").fetchall()
    return render_template("admin_users.html", users=rows)


@bp.route("/users/<int:user_id>/role", methods=["POST"])
@require_permission("roles:manage")
def set_role(user_id):
    role = request.form.get("role", "")
    if role not in VALID_ROLES:
        abort(400)
    if user_id == g.user["user_id"]:
        flash("Vous ne pouvez pas modifier votre propre rôle.")
        return redirect(url_for("admin.users"))
    if VALID_ROLES[role] != ADMIN_ROLE_ID and is_last_admin(user_id):
        log_event("LAST_ADMIN_PROTECTED", g.user["user_id"],
                  details=f"user {user_id}")
        flash("Impossible : c'est le dernier administrateur.")
        return redirect(url_for("admin.users"))
    db = get_db()
    cur = db.execute("UPDATE users SET role_id = ? WHERE id = ?",
                     (VALID_ROLES[role], user_id))
    db.commit()
    if cur.rowcount == 0:
        abort(404)
    log_event("ROLE_CHANGED", g.user["user_id"],
              details=f"user {user_id} -> {role}")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/unlock", methods=["POST"])
@require_permission("users:manage")
def unlock(user_id):
    db = get_db()
    db.execute("UPDATE users SET locked_until = NULL, failed_attempts = 0 "
               "WHERE id = ?", (user_id,))
    db.commit()
    log_event("ACCOUNT_UNLOCKED", g.user["user_id"], details=f"user {user_id}")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/delete", methods=["POST"])
@require_permission("users:manage")
def delete(user_id):
    if user_id == g.user["user_id"]:
        flash("Vous ne pouvez pas supprimer votre propre compte.")
        return redirect(url_for("admin.users"))
    if is_last_admin(user_id):
        log_event("LAST_ADMIN_PROTECTED", g.user["user_id"],
                  details=f"user {user_id}")
        flash("Impossible : c'est le dernier administrateur.")
        return redirect(url_for("admin.users"))
    db = get_db()
    cur = db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    if cur.rowcount == 0:
        abort(404)
    log_event("USER_DELETED", g.user["user_id"], details=f"user {user_id}")
    return redirect(url_for("admin.users"))
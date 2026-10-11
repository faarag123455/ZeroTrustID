import hashlib
import hmac
from datetime import datetime, timezone

from flask import (Blueprint, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import generate_password_hash

from app.extensions import limiter
from app.models.db import get_db
from app.security import backup_codes
from app.security.audit import log_event
from app.security.decorators import login_required
from app.security.passwords import validate_password_policy
from app.security.reauth import check_current_password
from app.security.sessions import create_session

bp = Blueprint("account", __name__, url_prefix="/profile")


# ---------------------------------------------------------------- Profil
@bp.route("/")
@login_required
def index():
    row = get_db().execute(
        "SELECT u.email, u.created_at, r.name AS role, "
        "(u.mfa_secret IS NOT NULL) AS mfa "
        "FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = ?",
        (g.user["user_id"],)).fetchone()
    return render_template("profile.html", u=row,
                           codes_left=backup_codes.remaining(g.user["user_id"]))


# ------------------------------------------------- Changement de mot de passe
@bp.route("/password", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
@login_required
def change_password():
    uid = g.user["user_id"]

    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        # 1. Revérification de l'identité
        status = check_current_password(uid, current)
        if status != "ok":
            log_event("PASSWORD_CHANGE_FAILED", uid, details=status)
            flash("Mot de passe actuel incorrect.")
            return render_template("change_password.html")

        # 2. Validation du nouveau mot de passe
        errors = validate_password_policy(new)
        if new != confirm:
            errors.append("La confirmation ne correspond pas.")
        if new == current:
            errors.append("Le nouveau mot de passe doit être différent "
                          "de l'ancien.")
        if errors:
            for e in errors:
                flash(e)
            return render_template("change_password.html")

        # 3. Mise à jour + révocation de TOUTES les sessions
        db = get_db()
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                   (generate_password_hash(new), uid))
        db.execute("DELETE FROM sessions WHERE user_id = ?", (uid,))
        db.commit()

        # 4. Nouvelle session pour cet appareil uniquement
        session.clear()
        session["sid"] = create_session(uid)
        session.permanent = True

        log_event("PASSWORD_CHANGED", uid, details="sessions revoquees")
        flash("Mot de passe modifié. Les autres appareils ont été déconnectés.")
        return redirect(url_for("account.index"))

    return render_template("change_password.html")


# ------------------------------------------------------------------- MFA
@bp.route("/mfa/disable", methods=["POST"])
@limiter.limit("5 per minute")
@login_required
def disable_mfa():
    uid = g.user["user_id"]
    status = check_current_password(uid, request.form.get("password", ""))
    if status != "ok":
        log_event("MFA_DISABLE_FAILED", uid, details=status)
        flash("Mot de passe incorrect : MFA conservée.")
        return redirect(url_for("account.index"))

    db = get_db()
    db.execute("UPDATE users SET mfa_secret = NULL WHERE id = ?", (uid,))
    db.commit()
    backup_codes.delete_all(uid)
    log_event("MFA_DISABLED", uid)
    flash("MFA désactivée.")
    return redirect(url_for("account.index"))


@bp.route("/mfa/backup-codes", methods=["POST"])
@limiter.limit("5 per minute")
@login_required
def regenerate_backup_codes():
    uid = g.user["user_id"]
    has_mfa = get_db().execute("SELECT mfa_secret FROM users WHERE id = ?",
                               (uid,)).fetchone()["mfa_secret"]
    if not has_mfa:
        abort(404)
    if check_current_password(uid, request.form.get("password", "")) != "ok":
        log_event("BACKUP_CODES_FAILED", uid)
        flash("Mot de passe incorrect.")
        return redirect(url_for("account.index"))
    codes = backup_codes.generate(uid)
    log_event("BACKUP_CODES_REGENERATED", uid)
    return render_template("backup_codes.html", codes=codes)


# -------------------------------------------------------- Sessions actives
def _ref(sid):
    """Référence publique d'une session (non réversible)."""
    return hashlib.sha256(sid.encode()).hexdigest()[:16]


def _active_sessions(uid):
    rows = get_db().execute(
        "SELECT id, created_at, expires_at, ip FROM sessions "
        "WHERE user_id = ? ORDER BY created_at DESC", (uid,)).fetchall()
    now = datetime.now(timezone.utc)
    return [r for r in rows
            if datetime.fromisoformat(r["expires_at"]) > now]


@bp.route("/sessions")
@login_required
def sessions():
    current = session.get("sid")
    items = [{"ref": _ref(r["id"]),
              "created_at": r["created_at"],
              "ip": r["ip"],
              "current": r["id"] == current}
             for r in _active_sessions(g.user["user_id"])]
    return render_template("sessions.html", items=items)


@bp.route("/sessions/<ref>/revoke", methods=["POST"])
@login_required
def revoke_session(ref):
    uid = g.user["user_id"]
    # On ne cherche que parmi les sessions de l'utilisateur connecté (anti-IDOR)
    target = next((r["id"] for r in _active_sessions(uid)
                   if hmac.compare_digest(_ref(r["id"]), ref)), None)
    if target is None:
        abort(404)

    db = get_db()
    db.execute("DELETE FROM sessions WHERE id = ? AND user_id = ?",
               (target, uid))
    db.commit()
    log_event("SESSION_REVOKED", uid, details="une session")

    if target == session.get("sid"):
        session.clear()
        return redirect(url_for("auth.login"))
    flash("Session révoquée.")
    return redirect(url_for("account.sessions"))


@bp.route("/sessions/revoke-others", methods=["POST"])
@login_required
def revoke_other_sessions():
    uid = g.user["user_id"]
    db = get_db()
    cur = db.execute("DELETE FROM sessions WHERE user_id = ? AND id != ?",
                     (uid, session.get("sid")))
    db.commit()
    log_event("SESSIONS_REVOKED_OTHERS", uid,
              details=f"{cur.rowcount} session(s)")
    flash(f"{cur.rowcount} autre(s) session(s) révoquée(s).")
    return redirect(url_for("account.sessions"))
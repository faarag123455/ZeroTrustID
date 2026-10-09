import re
import sqlite3
import time

from flask import (Blueprint, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import limiter
from app.models.db import get_db
from app.security import mfa
from app.security.audit import log_event
from app.security.decorators import login_required
from app.security.lockout import is_locked, register_failure, reset_failures
from app.security.passwords import validate_password_policy
from app.security.sessions import (create_session, destroy_session,
                                   get_valid_session)

bp = Blueprint("auth", __name__)

ROLE_USER = 1
PENDING_SECONDS = 300
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DUMMY_HASH = generate_password_hash("mot-de-passe-factice-pour-le-timing")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        errors = []
        if not EMAIL_RE.match(email) or len(email) > 254:
            errors.append("Email invalide.")
        errors += validate_password_policy(password)

        if not errors:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (email, password_hash, role_id) "
                    "VALUES (?, ?, ?)",
                    (email, generate_password_hash(password), ROLE_USER),
                )
                db.commit()
            except sqlite3.IntegrityError:
                errors.append("Inscription impossible avec ces informations.")
            else:
                flash("Compte créé. Vous pouvez vous connecter.")
                return redirect(url_for("auth.login"))

        for e in errors:
            flash(e)

    return render_template("register.html")


def finish_login(user_id):
    """Crée la vraie session serveur (après mot de passe, et OTP si activé)."""
    session.clear()
    session["sid"] = create_session(user_id)
    session.permanent = True
    log_event("LOGIN_SUCCESS", user_id)
    return redirect(url_for("auth.dashboard"))


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT id, password_hash, failed_attempts, locked_until, "
            "mfa_secret FROM users WHERE email = ?", (email,)).fetchone()

        hash_to_check = user["password_hash"] if user else DUMMY_HASH
        password_ok = check_password_hash(hash_to_check, password)
        locked = bool(user) and is_locked(user)

        if user and password_ok and not locked:
            session.clear()
            if user["mfa_secret"]:
                # Mot de passe OK, mais PAS encore connecté : on attend l'OTP.
                # On ne remet PAS le compteur à zéro ici (sinon T05 contourné).
                session["pending_user"] = user["id"]
                session["pending_at"] = time.time()
                return redirect(url_for("auth.login_otp"))
            reset_failures(user["id"])
            return finish_login(user["id"])

        if user and locked:
            log_event("LOGIN_BLOCKED", user["id"], details="compte bloque")
        else:
            log_event("LOGIN_FAILED", user["id"] if user else None,
                      details=f"email={email}")
            if user:
                register_failure(user)

        flash("Identifiants invalides.")

    return render_template("login.html")


@bp.route("/login/otp", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login_otp():
    uid = session.get("pending_user")
    if not uid or time.time() - session.get("pending_at", 0) > PENDING_SECONDS:
        session.clear()
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        user = get_db().execute(
            "SELECT id, failed_attempts, locked_until, mfa_secret "
            "FROM users WHERE id = ?", (uid,)).fetchone()

        if user is None or is_locked(user) or not user["mfa_secret"]:
            session.clear()
            return redirect(url_for("auth.login"))

        if mfa.verify_code(user["mfa_secret"], request.form.get("code", "")):
            reset_failures(user["id"])
            return finish_login(user["id"])

        log_event("MFA_FAILED", user["id"])
        register_failure(user)
        flash("Code invalide.")

    return render_template("otp.html")


@bp.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    if request.method == "POST":
        secret = session.get("mfa_pending_secret")
        if secret and mfa.verify_plain(secret, request.form.get("code", "")):
            db = get_db()
            db.execute("UPDATE users SET mfa_secret = ? WHERE id = ?",
                       (mfa.encrypt_secret(secret), g.user["user_id"]))
            db.commit()
            session.pop("mfa_pending_secret", None)
            log_event("MFA_ENABLED", g.user["user_id"])
            flash("MFA activée.")
            return redirect(url_for("auth.dashboard"))
        flash("Code invalide.")

    secret = session.get("mfa_pending_secret")
    if not secret:
        secret = mfa.new_secret()
        session["mfa_pending_secret"] = secret
    return render_template("mfa_setup.html",
                           qr=mfa.qr_data_uri(secret, g.user["email"]),
                           secret=secret)


@bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", email=g.user["email"])


@bp.route("/logout", methods=["POST"])
def logout():
    row = get_valid_session()
    log_event("LOGOUT", row["user_id"] if row else None)
    destroy_session()
    return redirect(url_for("auth.login"))
import re
import sqlite3

from flask import (Blueprint, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from app.models.db import get_db
from app.security.audit import log_event
from app.security.decorators import login_required
from app.security.passwords import validate_password_policy
from app.security.sessions import (create_session, destroy_session,
                                   get_valid_session)

bp = Blueprint("auth", __name__)

ROLE_USER = 1
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Hachage factice : même travail quand l'email n'existe pas (T06)
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


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT id, password_hash FROM users WHERE email = ?",
            (email,)).fetchone()

        hash_to_check = user["password_hash"] if user else DUMMY_HASH
        password_ok = check_password_hash(hash_to_check, password)

        if user and password_ok:
            session.clear()
            session["sid"] = create_session(user["id"])
            session.permanent = True
            log_event("LOGIN_SUCCESS", user["id"])
            return redirect(url_for("auth.dashboard"))

        log_event("LOGIN_FAILED", user["id"] if user else None,
                  details=f"email={email}")
        flash("Identifiants invalides.")

    return render_template("login.html")


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
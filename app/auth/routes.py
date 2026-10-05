import re
import sqlite3

from flask import Blueprint, flash, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash

from app.models.db import get_db
from app.security.passwords import validate_password_policy

bp = Blueprint("auth", __name__)

ROLE_USER = 1
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


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
                # Message volontairement vague : pas d'énumération (T06)
                errors.append("Inscription impossible avec ces informations.")
            else:
                flash("Compte créé. Vous pouvez vous connecter.")
                return redirect(url_for("auth.register"))

        for e in errors:
            flash(e)

    return render_template("register.html")
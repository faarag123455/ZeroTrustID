from flask import (Blueprint, abort, flash, g, redirect, render_template,
                   request, url_for)

from app.models.db import get_db
from app.security.audit import log_event
from app.security.crypto import decrypt, encrypt
from app.security.decorators import require_permission

bp = Blueprint("documents", __name__, url_prefix="/documents")

MAX_LEN = 5000


@bp.route("/")
@require_permission("documents:read")
def index():
    rows = get_db().execute(
        "SELECT id, created_at FROM encrypted_data "
        "WHERE user_id = ? ORDER BY id DESC",
        (g.user["user_id"],)).fetchall()
    return render_template("documents.html", docs=rows)


@bp.route("/new", methods=["GET", "POST"])
@require_permission("documents:read")
def new():
    if request.method == "POST":
        text = request.form.get("content", "").strip()
        if not text or len(text) > MAX_LEN:
            flash(f"Contenu requis (max {MAX_LEN} caractères).")
        else:
            db = get_db()
            db.execute(
                "INSERT INTO encrypted_data (user_id, ciphertext, hmac) "
                "VALUES (?, ?, ?)",
                (g.user["user_id"], encrypt(text.encode()), ""))
            db.commit()
            return redirect(url_for("documents.index"))
    return render_template("document_new.html")


@bp.route("/<int:doc_id>")
@require_permission("documents:read")
def view(doc_id):
    # Anti-IDOR : le filtre par propriétaire est dans la requête elle-même
    row = get_db().execute(
        "SELECT id, ciphertext FROM encrypted_data "
        "WHERE id = ? AND user_id = ?",
        (doc_id, g.user["user_id"])).fetchone()
    if row is None:
        log_event("ACCESS_DENIED", g.user["user_id"],
                  details=f"document {doc_id}")
        abort(404)
    content = decrypt(row["ciphertext"]).decode()
    return render_template("document_view.html", doc_id=row["id"],
                           content=content)
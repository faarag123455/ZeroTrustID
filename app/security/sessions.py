import secrets
from datetime import datetime, timezone

from flask import current_app, request, session

from app.models.db import get_db


def _now():
    return datetime.now(timezone.utc)


def create_session(user_id):
    """Crée une session côté serveur et retourne son identifiant."""
    sid = secrets.token_urlsafe(32)           # 256 bits aléatoires
    expires = _now() + current_app.config["PERMANENT_SESSION_LIFETIME"]
    db = get_db()
    db.execute(
        "INSERT INTO sessions (id, user_id, expires_at, ip) VALUES (?, ?, ?, ?)",
        (sid, user_id, expires.isoformat(), request.remote_addr),
    )
    db.commit()
    return sid


def get_valid_session():
    """Retourne la ligne (user_id, email) si la session est valide, sinon None."""
    sid = session.get("sid")
    if not sid:
        return None
    db = get_db()
    row = db.execute(
        "SELECT s.user_id, s.expires_at, u.email "
        "FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.id = ?", (sid,)).fetchone()
    if row is None:
        return None
    if datetime.fromisoformat(row["expires_at"]) <= _now():
        db.execute("DELETE FROM sessions WHERE id = ?", (sid,))
        db.commit()
        return None
    return row


def destroy_session():
    """Supprime la session en base ET vide le cookie."""
    sid = session.get("sid")
    if sid:
        db = get_db()
        db.execute("DELETE FROM sessions WHERE id = ?", (sid,))
        db.commit()
    session.clear()
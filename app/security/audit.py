import re

from flask import request

from app.models.db import get_db

MAX_DETAILS = 200


def _clean(text):
    """Retire les retours à la ligne et caractères de contrôle, puis tronque."""
    if text is None:
        return None
    text = re.sub(r"[\x00-\x1f\x7f]", " ", str(text))
    return text[:MAX_DETAILS]


def log_event(event_type, user_id=None, details=None):
    """Enregistre un événement de sécurité. Ne lève jamais d'exception."""
    try:
        db = get_db()
        db.execute(
            "INSERT INTO security_logs (event_type, user_id, ip, details) "
            "VALUES (?, ?, ?, ?)",
            (event_type, user_id, request.remote_addr, _clean(details)),
        )
        db.commit()
    except Exception:
        pass
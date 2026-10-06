from datetime import datetime, timedelta, timezone

from app.models.db import get_db
from app.security.audit import log_event

MAX_ATTEMPTS = 5
LOCK_MINUTES = 15


def _now():
    return datetime.now(timezone.utc)


def is_locked(user_row):
    """user_row doit contenir la colonne locked_until."""
    locked_until = user_row["locked_until"]
    if not locked_until:
        return False
    return datetime.fromisoformat(locked_until) > _now()


def register_failure(user_row):
    """Incrémente le compteur ; bloque le compte au seuil."""
    db = get_db()
    attempts = user_row["failed_attempts"] + 1
    if attempts >= MAX_ATTEMPTS:
        until = (_now() + timedelta(minutes=LOCK_MINUTES)).isoformat()
        db.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = ? "
            "WHERE id = ?", (until, user_row["id"]))
        db.commit()
        log_event("ACCOUNT_LOCKED", user_row["id"],
                  details=f"{LOCK_MINUTES} minutes")
    else:
        db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?",
                   (attempts, user_row["id"]))
        db.commit()


def reset_failures(user_id):
    db = get_db()
    db.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL "
        "WHERE id = ?", (user_id,))
    db.commit()
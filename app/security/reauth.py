from werkzeug.security import check_password_hash

from app.models.db import get_db
from app.security.lockout import is_locked, register_failure, reset_failures


def check_current_password(user_id, password):
    """Revérifie le mot de passe d'un utilisateur déjà connecté.

    Retourne "ok", "bad" ou "locked". Un échec compte dans le même
    compteur que la connexion (blocage après 5 échecs).
    """
    row = get_db().execute(
        "SELECT id, password_hash, failed_attempts, locked_until "
        "FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        return "bad"

    password_ok = check_password_hash(row["password_hash"], password)
    if is_locked(row):
        return "locked"
    if password_ok:
        reset_failures(user_id)
        return "ok"
    register_failure(row)
    return "bad"
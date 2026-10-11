import hashlib
import hmac
import secrets

from flask import current_app

from app.models.db import get_db

COUNT = 8
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # sans 0/O/1/I


def _hash(code):
    """HMAC avec HMAC_KEY : rapide mais inexploitable sans la clé.
    Les codes ont 40 bits d'entropie, d'où ce choix plutôt que scrypt."""
    return hmac.new(current_app.config["HMAC_KEY"], code.encode(),
                    hashlib.sha256).hexdigest()


def _normalize(code):
    return (code or "").upper().replace("-", "").replace(" ", "")


def _new_code():
    raw = "".join(secrets.choice(ALPHABET) for _ in range(8))
    return raw[:4] + "-" + raw[4:]


def generate(user_id):
    """Remplace les codes de l'utilisateur et retourne les nouveaux (clair)."""
    db = get_db()
    db.execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))
    codes = [_new_code() for _ in range(COUNT)]
    for c in codes:
        db.execute("INSERT INTO backup_codes (user_id, code_hash) "
                   "VALUES (?, ?)", (user_id, _hash(_normalize(c))))
    db.commit()
    return codes


def consume(user_id, code):
    """True si le code est valide et non utilisé ; il est alors consommé."""
    code = _normalize(code)
    if len(code) != 8 or any(ch not in ALPHABET for ch in code):
        return False
    db = get_db()
    cur = db.execute(
        "UPDATE backup_codes SET used_at = CURRENT_TIMESTAMP "
        "WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
        (user_id, _hash(code)))
    db.commit()
    return cur.rowcount == 1


def remaining(user_id):
    return get_db().execute(
        "SELECT COUNT(*) FROM backup_codes "
        "WHERE user_id = ? AND used_at IS NULL", (user_id,)).fetchone()[0]


def delete_all(user_id):
    db = get_db()
    db.execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))
    db.commit()
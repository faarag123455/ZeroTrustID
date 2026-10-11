"""Journal de sécurité chaîné (HMAC-SHA256) avec ancre externe.

Chaque entrée porte :
    previous_hash : current_hash de l'entrée précédente (GENESIS pour la 1re)
    current_hash  : HMAC-SHA256(HMAC_KEY, représentation canonique de l'entrée)

Modifier ou supprimer une entrée en dehors de l'application casse la chaîne
(détection). Rien n'empêche la modification elle-même (prévention).
"""
import hashlib
import hmac
import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone

from flask import current_app, has_request_context, request

from app.models.db import get_db

log = logging.getLogger(__name__)

GENESIS = "0" * 64              # valeur initiale documentée de la chaîne
CHAIN_VERSION = 1               # versionne le format canonique
MAX_DETAILS = 200
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


# ------------------------------------------------------------- primitives
def _clean(text):
    """Retire retours à la ligne et caractères de contrôle, puis tronque."""
    if text is None:
        return None
    text = re.sub(r"[\x00-\x1f\x7f]", " ", str(text))
    return text[:MAX_DETAILS]


def _mac(data: bytes) -> str:
    return hmac.new(current_app.config["HMAC_KEY"], data,
                    hashlib.sha256).hexdigest()


def _canonical(prev_hash, row_id, created_at, event_type, user_id, ip,
               details) -> bytes:
    """Représentation déterministe de l'entrée (current_hash exclu)."""
    return json.dumps(
        [CHAIN_VERSION, prev_hash, row_id, created_at, event_type, user_id,
         ip, details],
        ensure_ascii=True, separators=(",", ":")).encode()


def _entry_hash(prev_hash, row_id, created_at, event_type, user_id, ip,
                details) -> str:
    return _mac(_canonical(prev_hash, row_id, created_at, event_type,
                           user_id, ip, details))


def _remote_ip():
    return request.remote_addr if has_request_context() else "cli"


# ------------------------------------------------------------------ ancre
def _anchor_payload(row_id, entry_hash):
    return {"id": row_id, "hash": entry_hash,
            "mac": _mac(f"anchor|{row_id}|{entry_hash}".encode())}


def _write_anchor(row_id, entry_hash):
    """Écriture atomique de l'ancre. N'interrompt jamais l'application."""
    path = current_app.config.get("LOG_ANCHOR_PATH")
    if not path:
        return
    try:
        folder = os.path.dirname(path) or "."
        os.makedirs(folder, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=folder, prefix=".anchor-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(_anchor_payload(row_id, entry_hash), f)
        os.replace(tmp, path)
    except Exception:
        log.exception("Écriture de l'ancre d'intégrité impossible")


def _read_anchor():
    """Retourne (statut, données) : disabled | missing | invalid | ok."""
    path = current_app.config.get("LOG_ANCHOR_PATH")
    if not path:
        return "disabled", None
    if not os.path.exists(path):
        return "missing", None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        rid, h, mac = data["id"], data["hash"], data["mac"]
        expected = _mac(f"anchor|{rid}|{h}".encode())
        if (isinstance(rid, int) and isinstance(h, str)
                and isinstance(mac, str)
                and hmac.compare_digest(expected, mac)):
            return "ok", {"id": rid, "hash": h}
        return "invalid", None
    except (OSError, ValueError, KeyError, TypeError):
        return "invalid", None


def reset_anchor():
    """Supprime l'ancre (appelé quand la base est réinitialisée)."""
    path = current_app.config.get("LOG_ANCHOR_PATH")
    if path and os.path.exists(path):
        os.remove(path)


# --------------------------------------------------------------- écriture
def log_event(event_type, user_id=None, details=None):
    """Seul point d'écriture du journal. Ne lève jamais d'exception."""
    db = None
    try:
        db = get_db()
        if not db.in_transaction:
            db.execute("BEGIN IMMEDIATE")      # verrou d'écriture
        head = db.execute(
            "SELECT id FROM security_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        last = db.execute(
            "SELECT current_hash FROM security_logs "
            "WHERE current_hash IS NOT NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()
        new_id = (head["id"] if head else 0) + 1
        prev = last["current_hash"] if last else GENESIS
        created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        uid = int(user_id) if user_id is not None else None
        ip = _remote_ip()
        details = _clean(details)
        h = _entry_hash(prev, new_id, created, event_type, uid, ip, details)
        db.execute(
            "INSERT INTO security_logs (id, event_type, user_id, ip, "
            "details, created_at, previous_hash, current_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (new_id, event_type, uid, ip, details, created, prev, h))
        db.commit()
    except Exception:
        log.exception("Écriture du journal de sécurité impossible")
        try:
            if db is not None:
                db.rollback()
        except Exception:
            log.exception("Annulation de la transaction impossible")
        return
    _write_anchor(new_id, h)


# ----------------------------------------------------------- vérification
def verify_chain():
    """Vérifie toute la chaîne. LECTURE SEULE : ne corrige jamais rien.

    Retourne un dictionnaire : ok, status, count, sealed, legacy,
    anomalies [{id, type, message}], head, anchor.
    """
    db = get_db()
    anomalies = []

    def add(row_id, kind, message):
        anomalies.append({"id": row_id, "type": kind, "message": message})

    count = sealed = legacy = 0
    expected_prev = GENESIS
    prev_row_id = last_id = None
    chain_started = False

    rows = db.execute(
        "SELECT id, created_at, event_type, user_id, ip, details, "
        "previous_hash, current_hash FROM security_logs ORDER BY id")
    for r in rows:
        count += 1
        rid = r["id"]
        if chain_started and prev_row_id is not None \
                and rid != prev_row_id + 1:
            add(rid, "ID_GAP",
                f"Les entrées n° {prev_row_id + 1} à {rid - 1} sont "
                "absentes : suppression détectée.")
        prev_row_id = last_id = rid

        cur, prv = r["current_hash"], r["previous_hash"]

        if cur is None and prv is None:
            if chain_started:
                add(rid, "UNSEALED_IN_CHAIN",
                    "Entrée sans empreinte au milieu de la chaîne "
                    "(insertion ou effacement des empreintes).")
            else:
                legacy += 1            # antérieure à la chaîne : non protégée
            continue

        chain_started = True
        sealed += 1

        if not (isinstance(cur, str) and HASH_RE.match(cur)
                and isinstance(prv, str) and HASH_RE.match(prv)):
            add(rid, "INVALID_HASH",
                "Empreinte absente ou mal formée.")
            continue

        if prv != expected_prev:
            add(rid, "CHAIN_BROKEN",
                "previous_hash ne correspond pas à l'entrée précédente "
                "(suppression, insertion ou modification).")

        recomputed = _entry_hash(prv, rid, r["created_at"], r["event_type"],
                                 r["user_id"], r["ip"], r["details"])
        if not hmac.compare_digest(recomputed, cur):
            add(rid, "CONTENT_MODIFIED",
                "Le contenu ou l'empreinte de cette entrée a été modifié.")

        expected_prev = cur

    # Ancre externe : détecte la suppression de la fin du journal
    anchor_status, anchor = _read_anchor()
    if anchor_status == "invalid":
        add(None, "ANCHOR_INVALID",
            "L'ancre est illisible ou sa signature est invalide.")
    elif anchor_status == "missing" and sealed:
        add(None, "ANCHOR_MISSING",
            "L'ancre est absente alors que la chaîne contient des entrées.")
    elif anchor_status == "ok":
        if last_id is None or anchor["id"] > last_id:
            add(anchor["id"], "TRUNCATION_DETECTED",
                f"L'ancre référence l'entrée n° {anchor['id']} mais la "
                f"dernière entrée est n° {last_id or 0} : la fin du "
                "journal a été supprimée.")
        else:
            row = db.execute(
                "SELECT current_hash FROM security_logs WHERE id = ?",
                (anchor["id"],)).fetchone()
            if row is None or row["current_hash"] != anchor["hash"]:
                add(anchor["id"], "ANCHOR_MISMATCH",
                    "L'empreinte de l'entrée ancrée ne correspond plus.")

    ok = not anomalies
    return {"ok": ok, "status": "verified" if ok else "violation",
            "count": count, "sealed": sealed, "legacy": legacy,
            "anomalies": anomalies,
            "head": expected_prev if sealed else None,
            "anchor": anchor_status}


# -------------------------------------------------------------- migration
def seal_legacy():
    """Chaîne les anciens journaux sans empreinte. Retourne leur nombre.

    ATTENTION : cela fige l'état actuel. Cela ne prouve PAS que ces entrées
    étaient intactes avant. Refusé si la chaîne contient déjà des entrées.
    """
    db = get_db()
    if db.execute("SELECT 1 FROM security_logs "
                  "WHERE current_hash IS NOT NULL LIMIT 1").fetchone():
        raise RuntimeError("La chaîne contient déjà des entrées scellées.")
    if not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")
    rows = db.execute(
        "SELECT id, created_at, event_type, user_id, ip, details "
        "FROM security_logs ORDER BY id").fetchall()
    prev = GENESIS
    for r in rows:
        h = _entry_hash(prev, r["id"], r["created_at"], r["event_type"],
                        r["user_id"], r["ip"], r["details"])
        db.execute("UPDATE security_logs SET previous_hash = ?, "
                   "current_hash = ? WHERE id = ?", (prev, h, r["id"]))
        prev = h
    db.commit()
    if rows:
        _write_anchor(rows[-1]["id"], prev)
    return len(rows)
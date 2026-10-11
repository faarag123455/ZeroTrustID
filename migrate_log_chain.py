"""Migre security_logs vers la chaîne d'intégrité (avec sauvegarde).

  python migrate_log_chain.py                 historique laissé non protégé
  python migrate_log_chain.py --seal-legacy   historique chaîné (voir README)
"""
import argparse
import os
import sqlite3
import sys
from datetime import datetime

from app import create_app
from app.security.audit import log_event, seal_legacy, verify_chain


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seal-legacy", action="store_true")
    args = parser.parse_args()

    app = create_app()
    db_path = app.config["DATABASE"]
    if not os.path.exists(db_path):
        sys.exit(f"Base introuvable : {db_path}")

    # 1. Sauvegarde obligatoire avant toute modification
    folder = os.path.join(os.path.dirname(db_path) or ".", "backups")
    os.makedirs(folder, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = os.path.join(folder, f"{os.path.basename(db_path)}-{stamp}.bak")
    src, dst = sqlite3.connect(db_path), sqlite3.connect(backup)
    with dst:
        src.backup(dst)
    src.close()
    dst.close()
    print("Sauvegarde :", backup)

    # 2. Ajout des colonnes (idempotent, aucune donnée supprimée)
    conn = sqlite3.connect(db_path)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(security_logs)")}
    for col in ("previous_hash", "current_hash"):
        if col not in cols:
            conn.execute(f"ALTER TABLE security_logs ADD COLUMN {col} TEXT")
            print("Colonne ajoutée :", col)
    conn.commit()
    conn.close()

    with app.app_context():
        # 3. Historique : laissé tel quel, ou chaîné sur demande explicite
        if args.seal_legacy:
            n = seal_legacy()
            print(f"{n} entrée(s) historique(s) chaînée(s) "
                  "(intégrité passée NON prouvée).")
        # 4. Démarrage de la chaîne
        log_event("LOG_CHAIN_ENABLED", None,
                  details="seal-legacy" if args.seal_legacy
                  else "historique non protégé")
        r = verify_chain()
        print(f"Vérification : {'OK' if r['ok'] else 'ANOMALIES'} · "
              f"{r['count']} entrées · {r['legacy']} historiques")
        for a in r["anomalies"]:
            print("  -", a["id"], a["type"], a["message"])


if __name__ == "__main__":
    main()
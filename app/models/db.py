import sqlite3

import click
from flask import current_app, g


def get_db():
    """Une connexion par requête, réutilisée via g."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    with current_app.open_resource("models/schema.sql") as f:
        db.executescript(f.read().decode("utf-8"))
    # Base neuve = chaîne neuve : l'ancienne ancre n'a plus de sens.
    from app.security.audit import reset_anchor
    reset_anchor()


@click.command("init-db")
def init_db_command():
    """Crée les tables et les données de départ (efface tout)."""
    init_db()
    click.echo("Base de données initialisée.")


@click.command("verify-logs")
def verify_logs_command():
    """Vérifie l'intégrité de la chaîne des journaux (lecture seule)."""
    from app.security.audit import verify_chain
    r = verify_chain()
    click.echo(f"Entrées : {r['count']} (chaînées : {r['sealed']}, "
               f"historiques : {r['legacy']}) · ancre : {r['anchor']}")
    if r["ok"]:
        click.echo("INTÉGRITÉ VÉRIFIÉE")
        return
    click.echo("VIOLATION D'INTÉGRITÉ DÉTECTÉE")
    for a in r["anomalies"]:
        click.echo(f"  - entrée {a['id']} · {a['type']} · {a['message']}")
    raise SystemExit(1)


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
    app.cli.add_command(verify_logs_command)
import os

from flask import Flask, render_template, request
from flask_wtf.csrf import CSRFError

from .config import Config
from .extensions import csrf, limiter
from .models import db
from .security import headers
from .security.audit import log_event


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)

    # Les tests existants postent sans jeton : CSRF désactivé en test,
    # sauf si le test l'active explicitement.
    if app.config.get("TESTING") and \
            "WTF_CSRF_ENABLED" not in (test_config or {}):
        app.config["WTF_CSRF_ENABLED"] = False

    # Les tests n'écrivent pas dans l'ancre réelle, sauf s'ils la demandent.
    if app.config.get("TESTING") and \
            "LOG_ANCHOR_PATH" not in (test_config or {}):
        app.config["LOG_ANCHOR_PATH"] = None

    os.makedirs(app.instance_path, exist_ok=True)
    db.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)
    headers.init_app(app)

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        log_event("CSRF_FAILED", None, details=request.path)
        return "Requête refusée.", 400

    # ---- Pages d'erreur génériques (aucun détail technique) ----
    def _error(code, title, message):
        return render_template("error.html", code=code, title=title,
                               message=message), code

    @app.errorhandler(403)
    def forbidden(e):
        return _error(403, "Accès refusé",
                      "Vous n'avez pas les droits nécessaires pour cette page.")

    @app.errorhandler(404)
    def not_found(e):
        return _error(404, "Page introuvable",
                      "La page demandée n'est pas disponible.")

    @app.errorhandler(500)
    def server_error(e):
        return _error(500, "Erreur interne",
                      "Une erreur est survenue. L'incident a été journalisé.")

    # ---- Barre de navigation : décidée côté serveur, à chaque page ----
    @app.context_processor
    def inject_nav_user():
        from .models.db import get_db
        from .security.decorators import has_permission
        from .security.sessions import get_valid_session

        row = get_valid_session()
        if row is None:
            return {"nav_user": None}
        uid = row["user_id"]
        role = get_db().execute(
            "SELECT r.name FROM users u JOIN roles r ON r.id = u.role_id "
            "WHERE u.id = ?", (uid,)).fetchone()
        return {"nav_user": {
            "email": row["email"],
            "role": role["name"] if role else "user",
            "can_users": has_permission(uid, "users:manage"),
            "can_logs": has_permission(uid, "logs:read"),
        }}

    from .auth import routes as auth_routes
    app.register_blueprint(auth_routes.bp)

    from .admin import routes as admin_routes
    app.register_blueprint(admin_routes.bp)

    from .documents import routes as documents_routes
    app.register_blueprint(documents_routes.bp)

    from .account import routes as account_routes
    app.register_blueprint(account_routes.bp)

    @app.route("/")
    def home():
        return "ZeroTrustID is running!"

    return app
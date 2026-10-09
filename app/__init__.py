import os

from flask import Flask, request
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

    os.makedirs(app.instance_path, exist_ok=True)
    db.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)
    headers.init_app(app)

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        log_event("CSRF_FAILED", None, details=request.path)
        return "Requête refusée.", 400

    from .auth import routes as auth_routes
    app.register_blueprint(auth_routes.bp)

    from .admin import routes as admin_routes
    app.register_blueprint(admin_routes.bp)

    from .documents import routes as documents_routes
    app.register_blueprint(documents_routes.bp)

    @app.route("/")
    def home():
        return "ZeroTrustID is running!"

    return app
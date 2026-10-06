import os
from flask import Flask
from .config import Config
from .models import db


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)
    db.init_app(app)

    from .auth import routes as auth_routes
    app.register_blueprint(auth_routes.bp)

    from .admin import routes as admin_routes
    app.register_blueprint(admin_routes.bp)

    @app.route("/")
    def home():
        return "ZeroTrustID is running!"

    return app
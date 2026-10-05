import os
from flask import Flask
from .config import Config


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)

    @app.route("/")
    def home():
        return "ZeroTrustID is running!"

    return app
import os
from datetime import timedelta
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(BASE_DIR, ".env"))


class Config:
    # Si une clé manque, l'application refuse de démarrer (KeyError) : c'est voulu.
    SECRET_KEY = os.environ["SECRET_KEY"]
    DATA_KEY = os.environ["DATA_KEY"]
    HMAC_KEY = os.environ["HMAC_KEY"].encode()

    DATABASE =     DATABASE = os.environ.get("DATABASE_PATH") or os.path.join(
        BASE_DIR, "instance", "zerotrustid.db")

    # Ancre d'intégrité des journaux : à placer HORS de la base.
    # En production : autre disque, autre machine ou stockage en lecture seule.
    LOG_ANCHOR_PATH = os.environ.get("LOG_ANCHOR_PATH") or os.path.join(
        BASE_DIR, "instance", "log_anchor.json")

    # Cookies de session durcis (S3)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE") == "1"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)
    RATELIMIT_STORAGE_URI = "memory://"
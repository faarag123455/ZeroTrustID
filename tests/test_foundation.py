import pytest
from app import create_app


@pytest.fixture
def client():
    app = create_app({"TESTING": True})
    return app.test_client()


def test_home_page_works(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"ZeroTrustID" in response.data


def test_session_cookie_is_hardened():
    app = create_app({"TESTING": True})
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() == 900


def test_secret_key_is_not_hardcoded():
    app = create_app({"TESTING": True})
    assert app.config["SECRET_KEY"] != "development-secret-key"
    assert len(app.config["SECRET_KEY"]) >= 32
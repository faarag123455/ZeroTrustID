import sqlite3

PW = "Str0ng!Password#2026"


def db_exec(app, sql, params=()):
    c = sqlite3.connect(app.config["DATABASE"])
    rows = c.execute(sql, params).fetchall()
    c.commit()
    c.close()
    return rows


def make_client(app, email, admin=False):
    c = app.test_client()
    c.post("/register", data={"email": email, "password": PW})
    if admin:
        db_exec(app, "UPDATE users SET role_id = 2 WHERE email = ?", (email,))
    c.post("/login", data={"email": email, "password": PW})
    return c


def user_id(app, email):
    return db_exec(app, "SELECT id FROM users WHERE email = ?", (email,))[0][0]


def events(app):
    return [r[0] for r in db_exec(
        app, "SELECT event_type FROM security_logs ORDER BY id")]
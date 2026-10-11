import json
import os
import threading

import pytest

from app import create_app
from app.models.db import init_db
from app.security.audit import (GENESIS, _anchor_payload, log_event,
                                seal_legacy, verify_chain)
from tests.helpers import db_exec, make_client

COLS = ("id, event_type, user_id, ip, details, created_at, "
        "previous_hash, current_hash")


@pytest.fixture
def app(tmp_path):
    app = create_app({"TESTING": True,
                      "DATABASE": str(tmp_path / "test.db"),
                      "RATELIMIT_ENABLED": False,
                      "LOG_ANCHOR_PATH": str(tmp_path / "anchor.json")})
    with app.app_context():
        init_db()
    return app


def add_logs(app, n=5):
    with app.test_request_context("/", environ_base={"REMOTE_ADDR": "10.0.0.1"}):
        for i in range(n):
            log_event("TEST_EVENT", None, f"detail {i}")


def check(app):
    with app.app_context():
        return verify_chain()


def kinds(r):
    return [(a["id"], a["type"]) for a in r["anomalies"]]


def anchor_path(app):
    return app.config["LOG_ANCHOR_PATH"]


def snapshot(app):
    return db_exec(app, f"SELECT {COLS} FROM security_logs ORDER BY id")


def add_legacy(app, n):
    for i in range(n):
        db_exec(app, "INSERT INTO security_logs (event_type, ip, details) "
                     "VALUES ('ANCIEN', '1.2.3.4', ?)", (f"vieux {i}",))


# ---------------------------------------------------------- fonctionnement
def test_new_events_are_chained(app):
    add_logs(app, 4)
    rows = db_exec(app, "SELECT id, previous_hash, current_hash "
                        "FROM security_logs ORDER BY id")
    assert [r[0] for r in rows] == [1, 2, 3, 4]
    assert rows[0][1] == GENESIS
    for i in range(1, 4):
        assert rows[i][1] == rows[i - 1][2]
    assert all(len(r[2]) == 64 for r in rows)


def test_valid_chain(app):
    add_logs(app, 5)
    r = check(app)
    assert r["ok"] and r["status"] == "verified"
    assert (r["count"], r["sealed"], r["legacy"]) == (5, 5, 0)
    assert r["anomalies"] == [] and len(r["head"]) == 64


def test_empty_database(app):
    r = check(app)
    assert r["ok"] and r["count"] == 0 and r["head"] is None


# ------------------------------------------------------------ modification
@pytest.mark.parametrize("column,value", [
    ("event_type", "X"), ("user_id", 42), ("ip", "6.6.6.6"),
    ("details", "effacé"), ("created_at", "2000-01-01 00:00:00")])
def test_modified_field_is_detected(app, column, value):
    add_logs(app, 5)
    db_exec(app, f"UPDATE security_logs SET {column} = ? WHERE id = 3",
            (value,))
    assert kinds(check(app)) == [(3, "CONTENT_MODIFIED")]


def test_modified_previous_hash(app):
    add_logs(app, 5)
    db_exec(app, "UPDATE security_logs SET previous_hash = ? WHERE id = 3",
            ("a" * 64,))
    assert set(kinds(check(app))) == {(3, "CHAIN_BROKEN"),
                                      (3, "CONTENT_MODIFIED")}


def test_modified_current_hash(app):
    add_logs(app, 5)
    db_exec(app, "UPDATE security_logs SET current_hash = ? WHERE id = 3",
            ("b" * 64,))
    assert set(kinds(check(app))) == {(3, "CONTENT_MODIFIED"),
                                      (4, "CHAIN_BROKEN")}


def test_malformed_hash(app):
    add_logs(app, 5)
    db_exec(app, "UPDATE security_logs SET current_hash = 'xyz' WHERE id = 3")
    r = check(app)
    assert not r["ok"] and (3, "INVALID_HASH") in kinds(r)


def test_hash_removed_but_previous_kept(app):
    add_logs(app, 5)
    db_exec(app, "UPDATE security_logs SET current_hash = NULL WHERE id = 3")
    assert (3, "INVALID_HASH") in kinds(check(app))


def test_both_hashes_erased_inside_chain(app):
    add_logs(app, 5)
    db_exec(app, "UPDATE security_logs SET previous_hash = NULL, "
                 "current_hash = NULL WHERE id = 3")
    r = check(app)
    assert (3, "UNSEALED_IN_CHAIN") in kinds(r) and not r["ok"]


# ------------------------------------------------------------- suppression
def test_deleted_middle_entry(app):
    add_logs(app, 5)
    db_exec(app, "DELETE FROM security_logs WHERE id = 3")
    assert set(kinds(check(app))) == {(4, "ID_GAP"), (4, "CHAIN_BROKEN")}


def test_deleted_first_entry(app):
    add_logs(app, 5)
    db_exec(app, "DELETE FROM security_logs WHERE id = 1")
    r = check(app)
    assert not r["ok"] and (2, "CHAIN_BROKEN") in kinds(r)


# --------------------------------------------------------------- insertion
def test_forged_entry_inserted(app):
    add_logs(app, 5)
    db_exec(app, "INSERT INTO security_logs (id, event_type, user_id, ip, "
                 "details, created_at, previous_hash, current_hash) VALUES "
                 "(6, 'LOGIN_SUCCESS', 1, '1.1.1.1', 'forged', "
                 "'2026-01-01 00:00:00', ?, ?)", ("c" * 64, "d" * 64))
    r = check(app)
    assert (6, "CHAIN_BROKEN") in kinds(r)
    assert (6, "CONTENT_MODIFIED") in kinds(r)


def test_unsealed_entry_inserted(app):
    add_logs(app, 5)
    db_exec(app, "INSERT INTO security_logs (id, event_type, ip) "
                 "VALUES (6, 'LOGIN_SUCCESS', '1.1.1.1')")
    assert kinds(check(app)) == [(6, "UNSEALED_IN_CHAIN")]


# ---------------------------------------------------------- anciens logs
def test_legacy_rows_then_chain_starts(app):
    add_legacy(app, 2)
    r = check(app)
    assert r["ok"] and r["legacy"] == 2 and r["sealed"] == 0
    add_logs(app, 3)
    r = check(app)
    assert r["ok"] and (r["legacy"], r["sealed"], r["count"]) == (2, 3, 5)
    first = db_exec(app, "SELECT previous_hash FROM security_logs "
                         "WHERE id = 3")[0][0]
    assert first == GENESIS


def test_seal_legacy_chains_old_rows(app):
    add_legacy(app, 3)
    with app.app_context():
        assert seal_legacy() == 3
    r = check(app)
    assert r["ok"] and r["legacy"] == 0 and r["sealed"] == 3


def test_seal_legacy_refused_when_chain_exists(app):
    add_logs(app, 2)
    with app.app_context():
        with pytest.raises(RuntimeError):
            seal_legacy()


# ------------------------------------------------------- clé et lecture seule
def test_wrong_key_cannot_validate_chain(app):
    add_logs(app, 3)
    app.config["HMAC_KEY"] = b"autre-cle-que-l-attaquant-croit-bonne"
    r = check(app)
    assert not r["ok"]
    assert {a["type"] for a in r["anomalies"]} >= {"CONTENT_MODIFIED"}


def test_verification_is_read_only(app):
    add_logs(app, 5)
    db_exec(app, "UPDATE security_logs SET ip = '6.6.6.6' WHERE id = 3")
    before = snapshot(app)
    anchor_before = open(anchor_path(app), encoding="utf-8").read()
    first, second = check(app), check(app)
    assert first == second and not first["ok"]
    assert snapshot(app) == before
    assert open(anchor_path(app), encoding="utf-8").read() == anchor_before


# ------------------------------------------------------------------- ancre
def test_anchor_matches_head(app):
    add_logs(app, 3)
    data = json.load(open(anchor_path(app), encoding="utf-8"))
    assert data["id"] == 3 and data["hash"] == check(app)["head"]


def test_truncation_is_detected_by_anchor(app):
    add_logs(app, 5)
    db_exec(app, "DELETE FROM security_logs WHERE id IN (4, 5)")
    assert kinds(check(app)) == [(5, "TRUNCATION_DETECTED")]


def test_missing_anchor(app):
    add_logs(app, 3)
    os.remove(anchor_path(app))
    assert kinds(check(app)) == [(None, "ANCHOR_MISSING")]


def test_edited_anchor_is_invalid(app):
    add_logs(app, 3)
    data = json.load(open(anchor_path(app), encoding="utf-8"))
    data["hash"] = "f" * 64
    json.dump(data, open(anchor_path(app), "w", encoding="utf-8"))
    assert kinds(check(app)) == [(None, "ANCHOR_INVALID")]


def test_forged_anchor_without_key_is_invalid(app):
    add_logs(app, 3)
    json.dump({"id": 1, "hash": "e" * 64, "mac": "0" * 64},
              open(anchor_path(app), "w", encoding="utf-8"))
    assert kinds(check(app)) == [(None, "ANCHOR_INVALID")]


def test_lagging_anchor_is_tolerated(app):
    add_logs(app, 3)
    old = open(anchor_path(app), encoding="utf-8").read()
    add_logs(app, 2)
    open(anchor_path(app), "w", encoding="utf-8").write(old)
    r = check(app)
    assert r["ok"] and r["anchor"] == "ok"


def test_anchor_mismatch(app):
    add_logs(app, 4)
    with app.app_context():
        payload = _anchor_payload(2, "e" * 64)
    json.dump(payload, open(anchor_path(app), "w", encoding="utf-8"))
    assert kinds(check(app)) == [(2, "ANCHOR_MISMATCH")]


def test_init_db_resets_anchor(app):
    add_logs(app, 2)
    assert os.path.exists(anchor_path(app))
    with app.app_context():
        init_db()
    assert not os.path.exists(anchor_path(app))


# ------------------------------------------------------------ page admin
def test_integrity_page_requires_admin(app):
    assert app.test_client().get("/admin/logs/integrity").status_code == 302
    c = make_client(app, "u@test.com")
    assert c.get("/admin/logs/integrity").status_code == 403
    assert c.post("/admin/logs/integrity").status_code == 403


def test_integrity_page_has_button_and_csrf_field(app):
    c = make_client(app, "admin@test.com", admin=True)
    r = c.get("/admin/logs/integrity")
    text = r.get_data(as_text=True)
    assert r.status_code == 200
    assert 'name="csrf_token"' in text and "Vérifier" in text


def test_admin_verification_ok(app):
    c = make_client(app, "admin@test.com", admin=True)
    text = c.post("/admin/logs/integrity").get_data(as_text=True)
    assert "Intégrité vérifiée" in text
    assert "Violation" not in text


def test_admin_verification_detects_tampering(app):
    c = make_client(app, "admin@test.com", admin=True)
    db_exec(app, "UPDATE security_logs SET ip = '6.6.6.6' WHERE id = 1")
    text = c.post("/admin/logs/integrity").get_data(as_text=True)
    assert "Violation d'intégrité détectée" in text
    assert "Contenu modifié" in text


def test_verification_only_appends_one_event(app):
    c = make_client(app, "admin@test.com", admin=True)
    before = snapshot(app)
    c.post("/admin/logs/integrity")
    after = snapshot(app)
    assert after[:len(before)] == before
    assert len(after) == len(before) + 1
    assert after[-1][1] == "LOG_INTEGRITY_CHECK"
    assert check(app)["ok"]


# ------------------------------------------------------------ concurrence
def test_concurrent_writes_keep_chain_valid(app):
    def worker(k):
        with app.test_request_context("/", environ_base={"REMOTE_ADDR": "10.0.0.2"}):
            for i in range(10):
                log_event("CONCURRENT", None, f"{k}-{i}")

    threads = [threading.Thread(target=worker, args=(k,)) for k in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    r = check(app)
    assert r["ok"] and r["count"] == 30
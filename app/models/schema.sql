PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS encrypted_data;
DROP TABLE IF EXISTS security_logs;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS backup_codes;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS roles;

CREATE TABLE roles (
    id   INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE permissions (
    id   INTEGER PRIMARY KEY,
    code TEXT UNIQUE NOT NULL
);

CREATE TABLE role_permissions (
    role_id       INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE users (
    id              INTEGER PRIMARY KEY,
    email           TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    role_id         INTEGER NOT NULL REFERENCES roles(id),
    mfa_secret      BLOB,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TIMESTAMP,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE backup_codes (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    TIMESTAMP
);


CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    ip         TEXT
);

CREATE TABLE security_logs (
    id            INTEGER PRIMARY KEY,
    event_type    TEXT NOT NULL,
    user_id       INTEGER,
    ip            TEXT,
    details       TEXT,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    previous_hash TEXT,
    current_hash  TEXT
);

CREATE TABLE encrypted_data (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ciphertext BLOB NOT NULL,
    hmac       TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO roles (id, name) VALUES (1, 'user'), (2, 'admin');

INSERT INTO permissions (id, code) VALUES
    (1, 'profile:read'),
    (2, 'documents:read'),
    (3, 'users:manage'),
    (4, 'roles:manage'),
    (5, 'logs:read');

INSERT INTO role_permissions (role_id, permission_id) VALUES (1, 1), (1, 2);
INSERT INTO role_permissions (role_id, permission_id) VALUES
    (2, 1), (2, 2), (2, 3), (2, 4), (2, 5);